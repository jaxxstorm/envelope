#!/usr/bin/env python3
"""Protected production-v3 controller conformance orchestration.

This legacy combined-evidence scaffold is blocked before live resource claims.
The approved replacement separates deployment/cleanup credentials from a
route-denied observer and labels deterministic harness evidence as simulated.
Do not enable this scaffold by declaring unsupported live capabilities true.
"""

from __future__ import annotations

import argparse
import base64
import copy
import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import os
import pathlib
import platform
import re
import shlex
import signal
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from typing import Any, NoReturn, Protocol, cast

from aws_appliance import (
    AwsCLI,
    RunConfig,
    SubprocessRunner,
    build_tailscale,
    delete_exact_object_versions,
    exact_object_versions,
    redact,
    tailnet_preflight,
    terraform_variables,
    validate_artifact,
)


EVIDENCE_SCHEMA = 2
EVIDENCE_KIND = "aws-production-controller-v3"
TOPOLOGY_SCHEMA = 1
TERRAFORM_VERSION = "1.10.5"
TERRAFORM_INIT_TIMEOUT_SECONDS = 300
TERRAFORM_PLAN_TIMEOUT_SECONDS = 1_800
TERRAFORM_APPLY_TIMEOUT_SECONDS = 3_600
TERRAFORM_OUTPUT_TIMEOUT_SECONDS = 300
TERRAFORM_CLEANUP_PLAN_TIMEOUT_SECONDS = 300
TERRAFORM_CLEANUP_APPLY_TIMEOUT_SECONDS = 1_200
CLEANUP_NON_TERRAFORM_MARGIN_SECONDS = 1_200
MAX_CLEANUP_TIMEOUT_SECONDS = 7_200
SSM_PARAMETER_RECONCILE_TIMEOUT_SECONDS = 30
SSM_PARAMETER_POLL_SECONDS = 1
SSM_PARAMETER_STABLE_READS = 2
SSM_PARAMETER_STABLE_ABSENCE_SECONDS = 5
EC2_FAULT_RESTORE_TIMEOUT_SECONDS = 300
EC2_FAULT_RESTORE_POLL_SECONDS = 2
EC2_FAULT_RUNNING_STABLE_READS = 2
EC2_FAULT_RUNNING_STABILITY_SECONDS = 5
EC2_FAULT_STOP_CALL_ARMED = "stop-call-armed"
EC2_FAULT_STOP_OBSERVED = "stop-observed"
EC2_FAULT_START_CALL_ARMED = "start-call-armed"
EC2_FAULT_RUNNING_PROVED = "running-proved"
EC2_FAULT_RESTORATION_PHASES = (
    EC2_FAULT_STOP_CALL_ARMED,
    EC2_FAULT_STOP_OBSERVED,
    EC2_FAULT_START_CALL_ARMED,
    EC2_FAULT_RUNNING_PROVED,
)
EXIT_OK = 0
EXIT_ACCEPTANCE_FAILED = 1
EXIT_CONTRACT_ERROR = 2
EXIT_CLEANUP_FAILED = 3
MAX_JSON_BYTES = 4 * 1024 * 1024
SSM_STDOUT_MAX_BYTES = 24_000
ESTABLISHED_AGENT_SCHEMA = 1
ESTABLISHED_MAX_MARKERS = 1_000
ESTABLISHED_STREAM_TRANSITIONS = 4
ESTABLISHED_STREAM_MARGIN_SECONDS = 180
ESTABLISHED_AGENT_MAX_TIMEOUT_SECONDS = 21_600
OBSERVATION_MARGIN_SECONDS = 5
CLEANUP_LEASE_MARGIN_SECONDS = 60
PROTECTED_SETUP_SAFETY_MARGIN_SECONDS = 1_800
AWS_MAX_ROLE_DURATION_SECONDS = 43_200
DEFAULT_AWS_ROLE_DURATION_SECONDS = 21_600
DEFAULT_JOB_TIMEOUT_SECONDS = 21_600
CONTROLLER_TSNET_ENV = "ENVELOPE_CONTROLLER_TSNET_AUTH_KEY"
CONTROLLER_ADMIN_ENV = "ENVELOPE_CONTROLLER_ADMIN_API_KEY"
RUNNER_DENY_ENV = "ENVELOPE_RUNNER_ROUTE_MUTATION_DENIED"
SESSION_ROUTE_DENY_EVIDENCE = "ec2:route-and-route-table-association-mutators"
STAGES = (
    "read-only-cold",
    "active-baseline",
    "lease-renewal",
    "observer-disagreement",
    "route-progress",
    "router-failover",
    "leader-handoff",
    "durable-alternate",
    "failback-gate",
    "failback-stable",
)
PHASES = {
    "stable",
    "owner-observed",
    "route-intent-persisted",
    "routes-converging",
    "degraded",
}
OUTCOMES = {"survived", "reset", "timed-out"}
RESET_ERROR_CATEGORIES = {
    "broken-pipe",
    "connection-aborted",
    "connection-reset",
    "peer-closed",
}
TIMEOUT_ERROR_CATEGORIES = {"deadline-exceeded", "socket-timeout"}
SSM_TERMINAL_STATUSES = {"Success", "Failed", "Cancelled", "TimedOut"}
REQUIRED_SCENARIO_CAPABILITIES = (
    "observer-disagreement",
    "lease-renewal",
    "in-progress-leader-failure",
    "stale-fence-rejection",
    "ambiguous-settlement",
)
RESIDUAL_AUDIT_HOOKS = (
    "aws-tagged-resources",
    "ssm-secret-references",
    "controller-artifact-versions",
    "tailnet-devices",
    "tailscale-auth-keys",
)
COMPLETE_CLEANUP_SEQUENCE = (
    "restore-faults",
    "quiesce-controller",
    "destroy-controller",
    "delete-controller-material",
    "destroy-appliance",
    "cleanup-tailnet",
    "audit-zero-residual",
    "finalize-backend",
)
AWS_CREDENTIAL_ENVIRONMENT_NAMES = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
)
READINESS_REASONS = {
    "ok",
    "ready",
    "process-not-live",
    "observer-not-running",
    "observer-unhealthy",
    "store-unavailable",
    "observation-unavailable",
    "observation-stale",
    "domain-status-missing",
    "domain-status-unknown",
    "domain-status-stale",
    "domain-degraded",
    "domain-unsafe",
    "domain-not-initialized",
    "domain-not-activated",
    "lease-lost",
    "lease-unsafe",
    "observation-quorum",
    "observation-no-quorum",
    "observation-invalid",
    "observation-disagreement",
    "owner-unknown",
    "owner-unhealthy",
    "owner-ineligible",
    "route-unauthorized",
    "route-ambiguous",
    "route-oscillation",
    "route-disagreement",
    "canceled",
    "invariant-violation",
    "unavailable",
}
_RUN_RE = re.compile(r"[a-z][a-z0-9-]{2,17}[a-z0-9]")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_INSTANCE_RE = re.compile(r"i-[0-9a-f]{8,17}")
_ENI_RE = re.compile(r"eni-[0-9a-f]{8,17}")
_VPC_RE = re.compile(r"vpc-[0-9a-f]{8,17}")
_SUBNET_RE = re.compile(r"subnet-[0-9a-f]{8,17}")
_ROUTE_TABLE_RE = re.compile(r"rtb-[0-9a-f]{8,17}")
_ASSOCIATION_RE = re.compile(r"rtbassoc-[0-9a-f]{8,17}")
_AMI_RE = re.compile(r"ami-[0-9a-f]{8,17}")
_REGION_RE = re.compile(r"[a-z][a-z0-9-]+-[0-9]+")
_SHA_RE = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_RUNTIME_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z"
)
_DURATION_RE = re.compile(r"([1-9][0-9]*)(ms|s|m|h)")
_SECRET_PATTERNS = (
    re.compile(r"(?i)tskey-[A-Za-z0-9_-]+"),
    re.compile(r"(?i)(?:nodekey|machinekey|privkey):[A-Za-z0-9+/=_-]+"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


class ContractError(RuntimeError):
    """A fail-closed configuration, adapter, or deployment contract error."""


class EvidenceError(ContractError):
    """Evidence is malformed or does not prove the acceptance contract."""


class MutationDenied(ContractError):
    """The acceptance identity attempted a controller-owned mutation."""


class HardTimeout(ContractError):
    """The acceptance window elapsed so ordered cleanup can begin."""


class CleanupTimeout(ContractError):
    """The separately reserved cleanup window elapsed."""


class BackendClaimUncertain(ContractError):
    """A conditional backend claim may exist but is not safely owned."""


class TerminationRequested(ContractError):
    """SIGTERM requested an orderly transition into protected cleanup."""


class ProtectedLifecycleDeadline:
    """Own separate acceptance and cleanup alarms and defer SIGTERM in cleanup."""

    def __init__(self, acceptance_seconds: int, cleanup_seconds: int):
        self.acceptance_seconds = acceptance_seconds
        self.cleanup_seconds = cleanup_seconds
        self.cleanup_started = False
        self.cleanup_finished = False
        self.termination_deferred = False
        self.acceptance_timeout_deferred = False
        self.cleanup_timeout_deferred = False
        self._handoff = False
        self._enabled = False
        self._previous_alarm_handler: Any = None
        self._previous_term_handler: Any = None
        self._previous_timer = (0.0, 0.0)

    def _alarm(self, _signum: int, _frame: Any) -> None:
        if self._handoff:
            if self.cleanup_started:
                self.cleanup_timeout_deferred = True
            else:
                self.acceptance_timeout_deferred = True
            return
        if self.cleanup_started and not self.cleanup_finished:
            raise CleanupTimeout("protected cleanup window elapsed")
        raise HardTimeout("protected acceptance window elapsed")

    def _terminate(self, _signum: int, _frame: Any) -> None:
        if not self.cleanup_finished and (self._handoff or self.cleanup_started):
            self.termination_deferred = True
            return
        raise TerminationRequested("protected acceptance received SIGTERM")

    def __enter__(self) -> "ProtectedLifecycleDeadline":
        if not hasattr(signal, "SIGALRM") or threading.current_thread() is not threading.main_thread():
            return self
        self._enabled = True
        self._previous_alarm_handler = signal.getsignal(signal.SIGALRM)
        self._previous_term_handler = signal.getsignal(signal.SIGTERM)
        self._previous_timer = signal.getitimer(signal.ITIMER_REAL)
        signal.signal(signal.SIGALRM, self._alarm)
        signal.signal(signal.SIGTERM, self._terminate)
        signal.setitimer(signal.ITIMER_REAL, self.acceptance_seconds)
        return self

    def start_cleanup(self) -> None:
        if self.cleanup_started:
            return
        self._handoff = True
        previous_mask: set[signal.Signals] | None = None
        blocked = {signal.SIGALRM, signal.SIGTERM}
        try:
            if self._enabled and hasattr(signal, "pthread_sigmask"):
                previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
            self.cleanup_started = True
            if self._enabled:
                signal.setitimer(signal.ITIMER_REAL, 0)
                if (
                    previous_mask is not None
                    and hasattr(signal, "sigpending")
                    and hasattr(signal, "sigwait")
                    and signal.SIGALRM in signal.sigpending()
                ):
                    self.acceptance_timeout_deferred = True
                    signal.sigwait({signal.SIGALRM})
                signal.setitimer(signal.ITIMER_REAL, self.cleanup_seconds)
        finally:
            if previous_mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            self._handoff = False

    def finish_cleanup(self) -> Mapping[str, bool]:
        if self.cleanup_finished:
            return {
                "termination_requested": self.termination_deferred,
                "acceptance_timed_out": self.acceptance_timeout_deferred,
                "cleanup_timed_out": self.cleanup_timeout_deferred,
            }
        self._handoff = True
        previous_mask: set[signal.Signals] | None = None
        blocked = {signal.SIGALRM, signal.SIGTERM}
        try:
            if self._enabled and hasattr(signal, "pthread_sigmask"):
                previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
            self.cleanup_finished = True
            if self._enabled:
                signal.setitimer(signal.ITIMER_REAL, 0)
                if (
                    previous_mask is not None
                    and hasattr(signal, "sigpending")
                    and hasattr(signal, "sigwait")
                    and signal.SIGALRM in signal.sigpending()
                ):
                    self.cleanup_timeout_deferred = True
                    signal.sigwait({signal.SIGALRM})
        finally:
            if previous_mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            self._handoff = False
        return {
            "termination_requested": self.termination_deferred,
            "acceptance_timed_out": self.acceptance_timeout_deferred,
            "cleanup_timed_out": self.cleanup_timeout_deferred,
        }

    def __exit__(
        self,
        _error_type: type[BaseException] | None,
        _error: BaseException | None,
        _traceback: Any,
    ) -> bool:
        if self._enabled:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, self._previous_alarm_handler)
            signal.signal(signal.SIGTERM, self._previous_term_handler)
            if self._previous_timer[0] > 0:
                signal.setitimer(signal.ITIMER_REAL, *self._previous_timer)
        return False


def _duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON number {value!r}")


def strict_json_loads(raw: str | bytes, label: str = "JSON") -> Any:
    if isinstance(raw, bytes):
        if len(raw) > MAX_JSON_BYTES:
            raise ContractError(f"{label} exceeds the bounded JSON size")
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ContractError(f"{label} is not UTF-8") from error
    elif len(raw.encode("utf-8")) > MAX_JSON_BYTES:
        raise ContractError(f"{label} exceeds the bounded JSON size")
    try:
        return json.loads(
            raw,
            object_pairs_hook=_duplicate_safe_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise ContractError(f"{label} is not strict JSON: {error}") from error


def load_json(path: pathlib.Path, label: str) -> Any:
    path = path.expanduser().resolve()
    if path.is_symlink() or not path.is_file():
        raise ContractError(f"{label} must be one regular non-symlink file")
    try:
        return strict_json_loads(path.read_bytes(), label)
    except OSError as error:
        raise ContractError(f"cannot read {label}: {error}") from error


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{label} must be an object")
    return dict(value)


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ContractError(f"{label} fields differ; missing={missing}, unsupported={extra}")


def _string(
    value: Any,
    label: str,
    *,
    pattern: re.Pattern[str] | None = None,
    maximum: int = 2048,
) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or pattern is not None
        and pattern.fullmatch(value) is None
    ):
        raise ContractError(f"{label} is invalid")
    return value


def _optional_string(
    value: Any, label: str, *, pattern: re.Pattern[str] | None = None
) -> str | None:
    if value is None:
        return None
    return _string(value, label, pattern=pattern)


def _integer(value: Any, label: str, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ContractError(f"{label} must be a whole number from {minimum} through {maximum}")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{label} must be boolean")
    return value


def _string_list(
    value: Any,
    label: str,
    *,
    minimum: int = 0,
    pattern: re.Pattern[str] | None = None,
    sorted_required: bool = False,
    unique_required: bool = True,
) -> list[str]:
    if not isinstance(value, list) or len(value) < minimum:
        raise ContractError(f"{label} must be a list with at least {minimum} entries")
    result = [_string(item, f"{label}[{index}]", pattern=pattern) for index, item in enumerate(value)]
    if unique_required and len(set(result)) != len(result):
        raise ContractError(f"{label} must not contain duplicates")
    if sorted_required and result != sorted(result):
        raise ContractError(f"{label} must be sorted")
    return result


def canonical_timestamp(value: Any, label: str) -> str:
    text = _string(value, label, pattern=_TIMESTAMP_RE, maximum=20)
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise ContractError(f"{label} must be canonical UTC RFC3339") from error
    if parsed.isoformat(timespec="seconds").replace("+00:00", "Z") != text:
        raise ContractError(f"{label} must be canonical UTC RFC3339")
    return text


def parse_timestamp(value: Any, label: str) -> dt.datetime:
    return dt.datetime.fromisoformat(canonical_timestamp(value, label)[:-1] + "+00:00")


def parse_runtime_timestamp(value: Any, label: str) -> dt.datetime:
    text = _string(value, label, pattern=_RUNTIME_TIMESTAMP_RE, maximum=40)
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise ContractError(f"{label} must be a UTC RFC3339 timestamp") from error
    if parsed.tzinfo != dt.timezone.utc:
        raise ContractError(f"{label} must be a UTC RFC3339 timestamp")
    return parsed


def evidence_runtime_timestamp(value: Any, label: str) -> str:
    return (
        parse_runtime_timestamp(value, label)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_duration(value: Any, label: str) -> float:
    text = _string(value, label, pattern=_DURATION_RE, maximum=16)
    match = _DURATION_RE.fullmatch(text)
    assert match is not None
    scale = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}[match.group(2)]
    seconds = int(match.group(1)) * scale
    if not 0.1 <= seconds <= 86400:
        raise ContractError(f"{label} must be between 100ms and 24h")
    return seconds


def protected_cleanup_bound_seconds(lease_duration_seconds: float) -> float:
    # Cleanup can perform one read-only controller apply and two destroys. Keep
    # their complete command bounds plus initialization, output, lease, and API work.
    return (
        lease_duration_seconds
        + 2 * TERRAFORM_INIT_TIMEOUT_SECONDS
        + 3 * TERRAFORM_CLEANUP_PLAN_TIMEOUT_SECONDS
        + 3 * TERRAFORM_CLEANUP_APPLY_TIMEOUT_SECONDS
        + TERRAFORM_OUTPUT_TIMEOUT_SECONDS
        + CLEANUP_NON_TERRAFORM_MARGIN_SECONDS
    )


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def route_snapshot_sha256(
    route_table: Mapping[str, Any], routes: Sequence[Mapping[str, Any]]
) -> str:
    return canonical_sha256(
        {
            name: route_table[name]
            for name in (
                "route_table_id",
                "vpc_id",
                "gwlbe_subnet_id",
                "route_table_association_id",
                "explicit_association_count",
                "association_state",
            )
        }
        | {"routes": list(routes)}
    )


def hash_identity(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_prefix(value: Any, label: str) -> str:
    text = _string(value, label, maximum=43)
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError as error:
        raise ContractError(f"{label} must be a canonical IPv4 prefix") from error
    if network.version != 4 or str(network) != text:
        raise ContractError(f"{label} must be a canonical IPv4 prefix")
    return text


def sanitize_text(
    value: Any, secrets: Sequence[str] = (), *, maximum: int = 512
) -> str:
    text = str(value)
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    text = redact(text)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    text = " ".join(text.split())
    return text[:maximum] if text else "unavailable"


def protected_environment_secrets(config: "ProductionRunConfig") -> tuple[str, ...]:
    names = (
        *config.appliance.oauth_environment_names,
        CONTROLLER_TSNET_ENV,
        CONTROLLER_ADMIN_ENV,
        *AWS_CREDENTIAL_ENVIRONMENT_NAMES,
    )
    return tuple(
        value
        for name in dict.fromkeys(names)
        if (value := os.environ.get(name, ""))
    )


@dataclasses.dataclass(frozen=True)
class ControllerSettings:
    region: str
    state_key: str
    vpc_id: str
    ami_id: str
    ami_trusted_owner_ids: tuple[str, ...]
    instance_type: str
    controller_ids: tuple[str, ...]
    placements: dict[str, dict[str, str]]
    management_egress: dict[str, dict[str, str]]
    secret_kms_key_arn: str
    metrics_ingress_cidrs: tuple[str, ...]
    metrics_port: int
    readiness_publisher: dict[str, Any]
    alarm_actions: tuple[str, ...]
    policy: dict[str, Any]
    policy_seconds: dict[str, float]
    state_base_dir: str
    control_url: str | None
    artifact_version: str
    timeouts: dict[str, int]


@dataclasses.dataclass(frozen=True)
class ProductionRunConfig:
    path: pathlib.Path
    raw: dict[str, Any]
    appliance: RunConfig
    controller: ControllerSettings
    run_id: str
    expires_at: str
    appliance_state_key: str
    configuration_sha256: str

    @classmethod
    def load(
        cls, path: pathlib.Path, *, enforce_future_expiry: bool = True
    ) -> "ProductionRunConfig":
        path = path.expanduser().resolve()
        raw = _mapping(load_json(path, "production run config"), "production run config")
        allowed = {
            "run_id",
            "expires_at",
            "architecture",
            "artifact_manifest",
            "instance_type",
            "test_instance_type",
            "tailscale_version",
            "tags",
            "backend",
            "symmetric_topology",
            "tailnet",
            "envelope",
            "cost",
            "e2e_load_profile",
            "production_controller",
        }
        required = allowed - {"tailscale_version", "tags", "cost"}
        if set(raw) - allowed or required - set(raw):
            raise ContractError(
                "production run config fields differ; "
                f"missing={sorted(required - set(raw))}, unsupported={sorted(set(raw) - allowed)}"
            )
        run_id = _string(raw.get("run_id"), "run_id", pattern=_RUN_RE, maximum=20)
        expires_at = canonical_timestamp(raw.get("expires_at"), "expires_at")
        if enforce_future_expiry:
            expiry = parse_timestamp(expires_at, "expires_at")
            now = dt.datetime.now(dt.timezone.utc)
            if not now + dt.timedelta(minutes=30) < expiry <= now + dt.timedelta(hours=24):
                raise ContractError("expires_at must be 30 minutes to 24 hours in the future")

        topology = _mapping(raw.get("symmetric_topology"), "symmetric_topology")
        if topology.get("version") != 3:
            raise ContractError(
                "the production controller runner accepts only symmetric_topology version 3; use aws_two_region_e2e.py for legacy version 2"
            )
        backend = _mapping(raw.get("backend"), "backend")
        appliance_state_key = _string(backend.get("state_key"), "backend.state_key")
        expected_appliance_key = f"runs/{run_id}/appliance/terraform.tfstate"
        if appliance_state_key != expected_appliance_key:
            raise ContractError(
                f"backend.state_key must be the run-owned appliance key {expected_appliance_key!r}"
            )

        controller = _parse_controller_settings(raw.get("production_controller"), run_id)
        if controller.state_key == appliance_state_key:
            raise ContractError("appliance and controller Terraform state keys must be distinct")

        # Reuse the mature network, cost, artifact-path, and Tailnet parser. Its
        # legacy version/state literals are replaced only in this private copy;
        # deployment always receives the original version-3 document and keys.
        legacy = copy.deepcopy(raw)
        legacy.pop("production_controller")
        cast(dict[str, Any], legacy["symmetric_topology"])["version"] = 2
        cast(dict[str, Any], legacy["backend"])["state_key"] = f"runs/{run_id}/terraform.tfstate"
        temporary_path: pathlib.Path | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".production-config-", suffix=".json", dir=path.parent
            )
            temporary_path = pathlib.Path(temporary_name)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(legacy, stream, sort_keys=True, separators=(",", ":"))
            os.chmod(temporary_path, 0o600)
            appliance = RunConfig.load(
                temporary_path, enforce_future_expiry=enforce_future_expiry
            )
        except (OSError, RuntimeError) as error:
            raise ContractError(str(error)) from error
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass
        appliance = dataclasses.replace(
            appliance,
            path=path,
            backend={**appliance.backend, "state_key": appliance_state_key},
        )
        normalized = copy.deepcopy(raw)
        configuration_sha256 = canonical_sha256(normalized)
        return cls(
            path=path,
            raw=normalized,
            appliance=appliance,
            controller=controller,
            run_id=run_id,
            expires_at=expires_at,
            appliance_state_key=appliance_state_key,
            configuration_sha256=configuration_sha256,
        )


def _parse_controller_settings(value: Any, run_id: str) -> ControllerSettings:
    document = _mapping(value, "production_controller")
    fields = {
        "region",
        "state_key",
        "vpc_id",
        "ami_id",
        "ami_trusted_owner_ids",
        "instance_type",
        "controller_ids",
        "placements",
        "management_egress",
        "secret_kms_key_arn",
        "metrics_ingress_cidrs",
        "metrics_port",
        "readiness_publisher",
        "alarm_actions",
        "policy",
        "state_base_dir",
        "control_url",
        "artifact_version",
        "timeouts",
    }
    _exact_keys(document, fields, "production_controller")
    region = _string(document["region"], "production_controller.region", pattern=_REGION_RE)
    state_key = _string(document["state_key"], "production_controller.state_key")
    expected_state_key = f"runs/{run_id}/controller/terraform.tfstate"
    if state_key != expected_state_key:
        raise ContractError(
            f"production_controller.state_key must be {expected_state_key!r}"
        )
    vpc_id = _string(document["vpc_id"], "production_controller.vpc_id", pattern=_VPC_RE)
    ami_id = _string(document["ami_id"], "production_controller.ami_id", pattern=_AMI_RE)
    owners = tuple(
        _string_list(
            document["ami_trusted_owner_ids"],
            "production_controller.ami_trusted_owner_ids",
            minimum=1,
            pattern=re.compile(r"[0-9]{12}"),
            sorted_required=True,
        )
    )
    instance_type = _string(
        document["instance_type"],
        "production_controller.instance_type",
        pattern=re.compile(r"[a-z0-9][a-z0-9.-]{1,31}"),
    )
    controller_ids = tuple(
        _string_list(
            document["controller_ids"],
            "production_controller.controller_ids",
            minimum=3,
            pattern=_ID_RE,
            sorted_required=True,
        )
    )
    if len(controller_ids) != 3:
        raise ContractError("production_controller.controller_ids must contain exactly three IDs")

    placements_value = _mapping(document["placements"], "production_controller.placements")
    if set(placements_value) != set(controller_ids):
        raise ContractError("production_controller.placements must exactly match controller_ids")
    placements: dict[str, dict[str, str]] = {}
    for controller_id in controller_ids:
        placement = _mapping(
            placements_value[controller_id],
            f"production_controller.placements.{controller_id}",
        )
        _exact_keys(
            placement,
            {"subnet_id", "availability_zone"},
            f"production_controller.placements.{controller_id}",
        )
        subnet_id = _string(
            placement["subnet_id"],
            f"production_controller.placements.{controller_id}.subnet_id",
            pattern=_SUBNET_RE,
        )
        availability_zone = _string(
            placement["availability_zone"],
            f"production_controller.placements.{controller_id}.availability_zone",
            pattern=re.compile(re.escape(region) + r"[a-z]"),
        )
        placements[controller_id] = {
            "subnet_id": subnet_id,
            "availability_zone": availability_zone,
        }
    if len({item["subnet_id"] for item in placements.values()}) != 3 or len(
        {item["availability_zone"] for item in placements.values()}
    ) != 3:
        raise ContractError("controller placements must use three unique subnets and AZs")

    egress_value = _mapping(
        document["management_egress"], "production_controller.management_egress"
    )
    if set(egress_value) != set(controller_ids):
        raise ContractError("production_controller.management_egress must exactly match controller_ids")
    egress_patterns = {
        "route_table_id": _ROUTE_TABLE_RE,
        "nat_gateway_id": re.compile(r"nat-[0-9a-f]{8,17}"),
        "nat_subnet_id": _SUBNET_RE,
        "nat_route_table_id": _ROUTE_TABLE_RE,
        "internet_gateway_id": re.compile(r"igw-[0-9a-f]{8,17}"),
    }
    management_egress: dict[str, dict[str, str]] = {}
    for controller_id in controller_ids:
        egress = _mapping(
            egress_value[controller_id],
            f"production_controller.management_egress.{controller_id}",
        )
        _exact_keys(
            egress,
            set(egress_patterns),
            f"production_controller.management_egress.{controller_id}",
        )
        management_egress[controller_id] = {
            name: _string(
                egress[name],
                f"production_controller.management_egress.{controller_id}.{name}",
                pattern=pattern,
            )
            for name, pattern in egress_patterns.items()
        }
    for field in ("route_table_id", "nat_gateway_id", "nat_subnet_id"):
        if len({item[field] for item in management_egress.values()}) != 3:
            raise ContractError(f"controller management egress {field} values must be unique")

    secret_kms_key_arn = _string(
        document["secret_kms_key_arn"],
        "production_controller.secret_kms_key_arn",
        pattern=re.compile(
            rf"arn:aws:kms:{re.escape(region)}:[0-9]{{12}}:key/(?:[0-9a-f-]{{36}}|mrk-[0-9a-f]{{32}})"
        ),
    )
    metrics_cidrs = tuple(
        _string_list(
            document["metrics_ingress_cidrs"],
            "production_controller.metrics_ingress_cidrs",
            minimum=1,
            sorted_required=True,
        )
    )
    for index, cidr in enumerate(metrics_cidrs):
        network = ipaddress.ip_network(_validate_prefix(cidr, f"metrics_ingress_cidrs[{index}]"))
        if not network.is_private or network.prefixlen == 0:
            raise ContractError("metrics_ingress_cidrs must contain only bounded private prefixes")
    metrics_port = _integer(
        document["metrics_port"], "production_controller.metrics_port", 1024, 65535
    )

    publisher = _mapping(
        document["readiness_publisher"], "production_controller.readiness_publisher"
    )
    _exact_keys(
        publisher,
        {"id", "role_name", "role_arn", "source_cidrs", "scrape_interval_seconds"},
        "production_controller.readiness_publisher",
    )
    readiness_publisher = {
        "id": _string(publisher["id"], "readiness_publisher.id", pattern=_ID_RE),
        "role_name": _string(publisher["role_name"], "readiness_publisher.role_name"),
        "role_arn": _string(
            publisher["role_arn"],
            "readiness_publisher.role_arn",
            pattern=re.compile(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+"),
        ),
        "source_cidrs": _string_list(
            publisher["source_cidrs"],
            "readiness_publisher.source_cidrs",
            minimum=1,
            sorted_required=True,
        ),
        "scrape_interval_seconds": _integer(
            publisher["scrape_interval_seconds"],
            "readiness_publisher.scrape_interval_seconds",
            10,
            300,
        ),
    }
    if not set(readiness_publisher["source_cidrs"]).issubset(metrics_cidrs):
        raise ContractError("readiness publisher source CIDRs must be allowed metrics CIDRs")
    alarm_actions = tuple(
        _string_list(
            document["alarm_actions"],
            "production_controller.alarm_actions",
            minimum=1,
            sorted_required=True,
        )
    )

    policy = _mapping(document["policy"], "production_controller.policy")
    policy_fields = {
        "replica_count",
        "observation_quorum",
        "observation_interval",
        "observation_freshness",
        "failover_stability",
        "failback_stability",
        "cooldown",
        "lease_duration",
        "lease_renew_interval",
        "lease_danger_window",
        "api_timeout",
        "route_convergence_timeout",
    }
    _exact_keys(policy, policy_fields, "production_controller.policy")
    if policy["replica_count"] != 3 or policy["observation_quorum"] != 2:
        raise ContractError("protected controller policy requires exactly three replicas and quorum two")
    durations = policy_fields - {"replica_count", "observation_quorum"}
    policy_seconds = {
        name: parse_duration(policy[name], f"production_controller.policy.{name}")
        for name in durations
    }
    if policy_seconds["observation_freshness"] < 2 * policy_seconds["observation_interval"]:
        raise ContractError("observation freshness must cover two observation intervals")
    if policy_seconds["failback_stability"] <= policy_seconds["failover_stability"]:
        raise ContractError("failback stability must exceed failover stability")
    action_bound = policy_seconds["api_timeout"] + policy_seconds["route_convergence_timeout"]
    if policy_seconds["lease_danger_window"] < action_bound:
        raise ContractError("lease danger window must cover API and convergence deadlines")
    if (
        policy_seconds["lease_renew_interval"] + policy_seconds["lease_danger_window"]
        >= policy_seconds["lease_duration"]
    ):
        raise ContractError("lease renewal plus danger window must be shorter than lease duration")

    state_base_dir = _string(
        document["state_base_dir"], "production_controller.state_base_dir", maximum=512
    )
    if (
        not state_base_dir.startswith("/var/lib/envelope-controller/")
        or ".." in pathlib.PurePosixPath(state_base_dir).parts
        or "//" in state_base_dir
    ):
        raise ContractError("controller state_base_dir must be a private clean absolute path")
    control_url = _optional_string(document["control_url"], "production_controller.control_url")
    if control_url is not None and not control_url.startswith("https://"):
        raise ContractError("production_controller.control_url must be HTTPS or null")
    artifact_version = _string(
        document["artifact_version"],
        "production_controller.artifact_version",
        pattern=re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,63}"),
    )
    timeout_value = _mapping(document["timeouts"], "production_controller.timeouts")
    _exact_keys(
        timeout_value,
        {"readiness_seconds", "transition_seconds", "cleanup_seconds"},
        "production_controller.timeouts",
    )
    timeouts = {
        name: _integer(
            value,
            f"production_controller.timeouts.{name}",
            30,
            MAX_CLEANUP_TIMEOUT_SECONDS if name == "cleanup_seconds" else 7200,
        )
        for name, value in timeout_value.items()
    }
    observation_margin = max(
        OBSERVATION_MARGIN_SECONDS, policy_seconds["observation_interval"]
    )
    if (
        timeouts["transition_seconds"]
        <= policy_seconds["lease_renew_interval"] + observation_margin
    ):
        raise ContractError(
            "transition timeout must exceed the lease renewal interval plus the observation margin"
        )
    cleanup_bound = max(
        policy_seconds["lease_duration"] + CLEANUP_LEASE_MARGIN_SECONDS,
        protected_cleanup_bound_seconds(policy_seconds["lease_duration"]),
    )
    if timeouts["cleanup_seconds"] <= cleanup_bound:
        raise ContractError(
            "cleanup timeout must cover lease expiry, all bounded Terraform cleanup operations, and the cleanup API margin"
        )
    stream_duration = (
        ESTABLISHED_STREAM_TRANSITIONS * timeouts["transition_seconds"]
        + ESTABLISHED_STREAM_MARGIN_SECONDS
    )
    if stream_duration > ESTABLISHED_AGENT_MAX_TIMEOUT_SECONDS:
        raise ContractError(
            "transition timeout cannot fit the established-flow scenario window"
        )
    return ControllerSettings(
        region=region,
        state_key=state_key,
        vpc_id=vpc_id,
        ami_id=ami_id,
        ami_trusted_owner_ids=owners,
        instance_type=instance_type,
        controller_ids=controller_ids,
        placements=placements,
        management_egress=management_egress,
        secret_kms_key_arn=secret_kms_key_arn,
        metrics_ingress_cidrs=metrics_cidrs,
        metrics_port=metrics_port,
        readiness_publisher=readiness_publisher,
        alarm_actions=alarm_actions,
        policy=copy.deepcopy(policy),
        policy_seconds=policy_seconds,
        state_base_dir=state_base_dir,
        control_url=control_url,
        artifact_version=artifact_version,
        timeouts=timeouts,
    )


@dataclasses.dataclass(frozen=True)
class TopologySeed:
    deployment_id: str
    sites: dict[str, dict[str, Any]]
    routers: tuple[dict[str, Any], ...]
    domains: tuple[dict[str, Any], ...]

    @property
    def routers_by_id(self) -> dict[str, dict[str, Any]]:
        return {str(router["id"]): dict(router) for router in self.routers}

    @property
    def domains_by_id(self) -> dict[str, dict[str, Any]]:
        return {str(domain["id"]): dict(domain) for domain in self.domains}


@dataclasses.dataclass(frozen=True)
class ApplianceDeployment:
    raw: dict[str, Any]
    output_sha256: str
    account_id: str
    artifact_bucket: str
    workloads: dict[str, dict[str, dict[str, str]]]
    seed: TopologySeed


def _output_value(document: Mapping[str, Any], name: str) -> Any:
    if name not in document:
        raise ContractError(f"Terraform output omitted {name}")
    wrapper = _mapping(document[name], f"Terraform output {name}")
    if "value" not in wrapper or set(wrapper) - {"value", "type", "sensitive"}:
        raise ContractError(f"Terraform output {name} has an invalid wrapper")
    return wrapper["value"]


def parse_appliance_output(value: Any, config: ProductionRunConfig) -> ApplianceDeployment:
    document = _mapping(value, "appliance Terraform output")
    seed = parse_topology_seed(_output_value(document, "production_controller_topology_seed"), config)
    artifact = _mapping(_output_value(document, "artifact_identity"), "artifact_identity")
    _exact_keys(
        artifact,
        {"bucket", "key", "sha256", "architecture", "ec2_arch", "revision", "version"},
        "artifact_identity",
    )
    artifact_bucket = _string(artifact["bucket"], "artifact_identity.bucket")
    if artifact["architecture"] != config.appliance.architecture:
        raise ContractError("appliance artifact architecture differs from config")

    workloads_value = _mapping(_output_value(document, "workload_instances"), "workload_instances")
    if set(workloads_value) != set(seed.sites):
        raise ContractError("workload sites differ from controller topology sites")
    workloads: dict[str, dict[str, dict[str, str]]] = {}
    workload_instance_ids: set[str] = set()
    workload_private_ips: set[str] = set()
    for site in sorted(workloads_value):
        roles = _mapping(workloads_value[site], f"workload_instances.{site}")
        if set(roles) != {"initiator", "responder"}:
            raise ContractError(f"workload_instances.{site} must contain initiator and responder")
        workloads[site] = {}
        for role in ("initiator", "responder"):
            workload = _mapping(roles[role], f"workload_instances.{site}.{role}")
            _exact_keys(
                workload,
                {
                    "instance_id",
                    "private_ip",
                    "az_key",
                    "availability_zone",
                    "subnet_id",
                    "cidr",
                    "route_table_id",
                },
                f"workload_instances.{site}.{role}",
            )
            cidr = _validate_prefix(workload["cidr"], f"workload_instances.{site}.{role}.cidr")
            try:
                address = ipaddress.ip_address(
                    _string(workload["private_ip"], f"workload_instances.{site}.{role}.private_ip")
                )
            except ValueError as error:
                raise ContractError("workload private IP is invalid") from error
            if address not in ipaddress.ip_network(cidr):
                raise ContractError("workload private IP is outside its exact prefix")
            instance_id = _string(
                workload["instance_id"],
                f"workload_instances.{site}.{role}.instance_id",
                pattern=_INSTANCE_RE,
            )
            subnet_id = _string(
                workload["subnet_id"],
                f"workload_instances.{site}.{role}.subnet_id",
                pattern=_SUBNET_RE,
            )
            route_table_id = _string(
                workload["route_table_id"],
                f"workload_instances.{site}.{role}.route_table_id",
                pattern=_ROUTE_TABLE_RE,
            )
            az_key = _string(
                workload["az_key"],
                f"workload_instances.{site}.{role}.az_key",
                pattern=re.compile(r"[a-z][a-z0-9-]{0,15}"),
            )
            region = str(seed.sites[site]["region"])
            availability_zone = _string(
                workload["availability_zone"],
                f"workload_instances.{site}.{role}.availability_zone",
                pattern=re.compile(re.escape(region) + r"[a-z]"),
            )
            configured_site = config.appliance.sites[site]
            expected_az_key = sorted(configured_site["azs"])[
                0 if role == "initiator" else 1
            ]
            if (
                az_key != expected_az_key
                or configured_site["azs"].get(az_key) != availability_zone
                or configured_site["workload_subnet_cidrs"].get(az_key) != cidr
                or cidr not in seed.sites[site]["local_prefixes"]
                or instance_id in workload_instance_ids
                or str(address) in workload_private_ips
            ):
                raise ContractError(
                    "workload cloud identity differs from its exact site and AZ authority"
                )
            workload_instance_ids.add(instance_id)
            workload_private_ips.add(str(address))
            workloads[site][role] = {
                "actor_id": f"{site}-{role}",
                "site_id": site,
                "role": role,
                "region": region,
                "vpc_id": str(seed.sites[site]["vpc_id"]),
                "instance_id": instance_id,
                "private_ip": str(address),
                "az_key": az_key,
                "availability_zone": availability_zone,
                "subnet_id": subnet_id,
                "cidr": cidr,
                "route_table_id": route_table_id,
            }
    if workload_instance_ids.intersection(
        str(router["instance_id"]) for router in seed.routers
    ):
        raise ContractError("workload and router instance identities overlap")
    account_id = _string(
        config.appliance.backend["kms_key_arn"].split(":")[4],
        "backend AWS account",
        pattern=re.compile(r"[0-9]{12}"),
    )
    return ApplianceDeployment(
        raw=document,
        output_sha256=canonical_sha256(document),
        account_id=account_id,
        artifact_bucket=artifact_bucket,
        workloads=workloads,
        seed=seed,
    )


def parse_topology_seed(value: Any, config: ProductionRunConfig) -> TopologySeed:
    document = _mapping(value, "production controller topology seed")
    _exact_keys(
        document,
        {"config_version", "deployment_id", "sites", "routers", "domains"},
        "production controller topology seed",
    )
    if document["config_version"] != 3 or document["deployment_id"] != config.run_id:
        raise ContractError("topology seed is not the approved version-3 deployment")
    sites_value = _mapping(document["sites"], "topology seed sites")
    if set(sites_value) != {"west", "east"}:
        raise ContractError("topology seed must contain exactly west and east")
    sites: dict[str, dict[str, Any]] = {}
    all_prefixes: dict[str, str] = {}
    for site_id in sorted(sites_value):
        site = _mapping(sites_value[site_id], f"topology seed site {site_id}")
        _exact_keys(
            site,
            {
                "vpc_id",
                "region",
                "local_prefixes",
                "local_main_rule_priority_base",
                "tailscale_route_rule_priority",
            },
            f"topology seed site {site_id}",
        )
        prefixes = [
            _validate_prefix(prefix, f"topology seed site {site_id} prefix")
            for prefix in _string_list(
                site["local_prefixes"],
                f"topology seed site {site_id} local_prefixes",
                minimum=1,
                sorted_required=True,
            )
        ]
        for prefix in prefixes:
            if prefix in all_prefixes:
                raise ContractError("topology seed local-prefix authority overlaps")
            network = ipaddress.ip_network(prefix)
            for prior in all_prefixes:
                if network.overlaps(ipaddress.ip_network(prior)):
                    raise ContractError("topology seed local-prefix authority overlaps")
            all_prefixes[prefix] = site_id
        base = _integer(site["local_main_rule_priority_base"], "local-main priority", 1, 32765)
        tailscale_priority = _integer(
            site["tailscale_route_rule_priority"], "Tailscale route priority", 1, 32765
        )
        if base + len(prefixes) - 1 >= tailscale_priority:
            raise ContractError("local-main priorities must precede the Tailscale route rule")
        sites[site_id] = {
            "vpc_id": _string(site["vpc_id"], f"site {site_id} VPC", pattern=_VPC_RE),
            "region": _string(site["region"], f"site {site_id} region", pattern=_REGION_RE),
            "local_prefixes": prefixes,
            "local_main_rule_priority_base": base,
            "tailscale_route_rule_priority": tailscale_priority,
        }

    if not isinstance(document["routers"], list):
        raise ContractError("topology seed routers must be a list")
    routers: list[dict[str, Any]] = []
    router_ids: set[str] = set()
    identities: dict[str, set[str]] = {"instance_id": set(), "eni_id": set(), "expected_hostname": set()}
    router_fields = {
        "id",
        "expected_hostname",
        "site_id",
        "instance_id",
        "eni_id",
        "vpc_id",
        "subnet_id",
        "availability_zone",
        "region",
    }
    for index, raw_router in enumerate(document["routers"]):
        router = _mapping(raw_router, f"topology seed router {index}")
        _exact_keys(router, router_fields, f"topology seed router {index}")
        router_id = _string(router["id"], f"router {index} ID", pattern=_ID_RE)
        site_id = _string(router["site_id"], f"router {router_id} site", pattern=_ID_RE)
        if router_id in router_ids or site_id not in sites:
            raise ContractError("topology seed contains duplicate router or unknown site")
        router_ids.add(router_id)
        normalized = {
            "id": router_id,
            "expected_hostname": _string(
                router["expected_hostname"], f"router {router_id} hostname", pattern=_ID_RE
            ),
            "site_id": site_id,
            "instance_id": _string(
                router["instance_id"], f"router {router_id} instance", pattern=_INSTANCE_RE
            ),
            "eni_id": _string(router["eni_id"], f"router {router_id} ENI", pattern=_ENI_RE),
            "vpc_id": _string(router["vpc_id"], f"router {router_id} VPC", pattern=_VPC_RE),
            "subnet_id": _string(
                router["subnet_id"], f"router {router_id} subnet", pattern=_SUBNET_RE
            ),
            "availability_zone": _string(
                router["availability_zone"],
                f"router {router_id} AZ",
                pattern=re.compile(re.escape(str(sites[site_id]["region"])) + r"[a-z]"),
            ),
            "region": _string(router["region"], f"router {router_id} region", pattern=_REGION_RE),
        }
        if (
            normalized["vpc_id"] != sites[site_id]["vpc_id"]
            or normalized["region"] != sites[site_id]["region"]
            or normalized["expected_hostname"]
            != f"{config.run_id}-{site_id}-transport-{router_id.removeprefix(site_id + '-')}"
        ):
            raise ContractError("router seed cloud or hostname identity differs from its site")
        for name in identities:
            if str(normalized[name]) in identities[name]:
                raise ContractError(f"topology seed duplicates router {name}")
            identities[name].add(str(normalized[name]))
        routers.append(normalized)
    if any(len([router for router in routers if router["site_id"] == site]) < 2 for site in sites):
        raise ContractError("each topology seed site requires at least two routers")

    if not isinstance(document["domains"], list):
        raise ContractError("topology seed domains must be a list")
    domains: list[dict[str, Any]] = []
    seen: dict[str, set[str]] = {
        "id": set(),
        "source_prefix": set(),
        "route_table_id": set(),
        "gwlbe_subnet_id": set(),
        "route_table_association_id": set(),
    }
    domain_fields = {
        "id",
        "site_id",
        "source_prefix",
        "route_table_id",
        "gwlbe_subnet_id",
        "route_table_association_id",
        "remote_prefixes",
        "preferred_owner",
    }
    for index, raw_domain in enumerate(document["domains"]):
        domain = _mapping(raw_domain, f"topology seed domain {index}")
        _exact_keys(domain, domain_fields, f"topology seed domain {index}")
        domain_id = _string(domain["id"], f"domain {index} ID", pattern=_ID_RE)
        site_id = _string(domain["site_id"], f"domain {domain_id} site", pattern=_ID_RE)
        source_prefix = _validate_prefix(domain["source_prefix"], f"domain {domain_id} source")
        remote_prefixes = [
            _validate_prefix(prefix, f"domain {domain_id} remote prefix")
            for prefix in _string_list(
                domain["remote_prefixes"],
                f"domain {domain_id} remote_prefixes",
                minimum=1,
                sorted_required=True,
            )
        ]
        preferred_owner = _string(
            domain["preferred_owner"], f"domain {domain_id} preferred owner", pattern=_ID_RE
        )
        normalized_domain = {
            "id": domain_id,
            "site_id": site_id,
            "source_prefix": source_prefix,
            "route_table_id": _string(
                domain["route_table_id"], f"domain {domain_id} route table", pattern=_ROUTE_TABLE_RE
            ),
            "gwlbe_subnet_id": _string(
                domain["gwlbe_subnet_id"], f"domain {domain_id} GWLBE subnet", pattern=_SUBNET_RE
            ),
            "route_table_association_id": _string(
                domain["route_table_association_id"],
                f"domain {domain_id} route association",
                pattern=_ASSOCIATION_RE,
            ),
            "remote_prefixes": remote_prefixes,
            "preferred_owner": preferred_owner,
        }
        if (
            site_id not in sites
            or all_prefixes.get(source_prefix) != site_id
            or set(remote_prefixes)
            != {prefix for prefix, prefix_site in all_prefixes.items() if prefix_site != site_id}
            or preferred_owner not in router_ids
            or next(router for router in routers if router["id"] == preferred_owner)["site_id"] != site_id
        ):
            raise ContractError("domain seed does not exactly cover site-local and remote authority")
        for name in seen:
            candidate = str(normalized_domain[name])
            if candidate in seen[name]:
                raise ContractError(f"topology seed duplicates domain {name}")
            seen[name].add(candidate)
        domains.append(normalized_domain)
    if seen["source_prefix"] != set(all_prefixes):
        raise ContractError("topology seed must contain one domain per local prefix")
    return TopologySeed(
        deployment_id=config.run_id,
        sites=sites,
        routers=tuple(sorted(routers, key=lambda item: str(item["id"]))),
        domains=tuple(sorted(domains, key=lambda item: str(item["id"]))),
    )


def build_controller_topology(
    seed: TopologySeed,
    devices: Sequence[Mapping[str, Any]],
    config: ProductionRunConfig,
    authority_table: str,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    by_hostname: dict[str, list[Mapping[str, Any]]] = {}
    for device in devices:
        hostname = str(device.get("hostname") or device.get("name") or "").split(".")[0]
        if hostname:
            by_hostname.setdefault(hostname, []).append(device)
    router_nodes: dict[str, dict[str, Any]] = {}
    stable_ids: set[str] = set()
    required_tag = config.appliance.tailnet["tag"]
    for router in seed.routers:
        matches = by_hostname.get(str(router["expected_hostname"]), [])
        if len(matches) != 1:
            raise ContractError("Tailnet does not contain one exact device for every topology router")
        device = matches[0]
        stable_id = _string(device.get("nodeId"), "Tailnet stable node ID")
        if stable_id.startswith(("nodekey:", "key:")) or stable_id in stable_ids:
            raise ContractError("Tailnet stable node IDs must be distinct non-key identities")
        stable_ids.add(stable_id)
        tags = device.get("tags")
        advertised = device.get("advertisedRoutes")
        enabled = device.get("enabledRoutes")
        expected = seed.sites[str(router["site_id"])]["local_prefixes"]
        if (
            device.get("authorized") is not True
            or not isinstance(tags, list)
            or required_tag not in tags
            or not isinstance(advertised, list)
            or not isinstance(enabled, list)
            or sorted(advertised) != expected
            or sorted(enabled) != expected
        ):
            raise ContractError(
                "Tailnet router must be authorized, tagged, and advertise and enable the complete exact site prefix set"
            )
        router_nodes[str(router["id"])] = {
            "stable_node_id": stable_id,
            "device_id": _string(device.get("id"), "Tailnet device ID"),
            "stable_node_sha256": hash_identity(stable_id),
        }

    topology = {
        "schema_version": TOPOLOGY_SCHEMA,
        "deployment_id": config.run_id,
        "controller_ids": list(config.controller.controller_ids),
        "policy": copy.deepcopy(config.controller.policy),
        "dynamodb": {"table": authority_table, "region": config.controller.region},
        "tailnet": {
            "name": config.appliance.tailnet["name"],
            **({"control_url": config.controller.control_url} if config.controller.control_url else {}),
            "tsnet_auth_key_env": CONTROLLER_TSNET_ENV,
            "admin_api_key_env": CONTROLLER_ADMIN_ENV,
            "state_base_dir": config.controller.state_base_dir,
        },
        "sites": [
            {
                "id": site_id,
                "vpc_id": seed.sites[site_id]["vpc_id"],
                "region": seed.sites[site_id]["region"],
                "local_prefixes": list(seed.sites[site_id]["local_prefixes"]),
            }
            for site_id in sorted(seed.sites)
        ],
        "routers": [
            {
                "id": router["id"],
                "site_id": router["site_id"],
                "stable_node_id": router_nodes[str(router["id"])]["stable_node_id"],
                "instance_id": router["instance_id"],
                "eni_id": router["eni_id"],
                "vpc_id": router["vpc_id"],
                "subnet_id": router["subnet_id"],
                "availability_zone": router["availability_zone"],
                "region": router["region"],
            }
            for router in seed.routers
        ],
        "domains": [copy.deepcopy(domain) for domain in seed.domains],
    }
    return topology, router_nodes


def validate_topology_identity(
    value: Any, topology: Mapping[str, Any], *, require_clean: bool = True
) -> dict[str, Any]:
    identity = _mapping(value, "topology identity")
    fields = {
        "schema",
        "component",
        "version",
        "revision",
        "go_version",
        "vcs_modified",
        "canonical_sha256",
        "canonical_json_base64",
        "policy_durations",
    }
    _exact_keys(identity, fields, "topology identity")
    if (
        identity["schema"] != 1
        or identity["component"] != "envelope-controller-topology"
        or require_clean
        and identity["vcs_modified"] is not False
    ):
        raise ContractError("topology identity has invalid release provenance")
    digest = _string(identity["canonical_sha256"], "topology identity SHA", pattern=_SHA_RE)
    encoded = _string(identity["canonical_json_base64"], "topology canonical base64", maximum=16384)
    try:
        canonical = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise ContractError("topology identity canonical bytes are invalid base64") from error
    if hashlib.sha256(canonical).hexdigest() != digest:
        raise ContractError("topology identity hash does not match canonical bytes")
    decoded = _mapping(strict_json_loads(canonical, "canonical topology"), "canonical topology")
    if decoded != topology:
        raise ContractError("topology identity does not contain the generated controller topology")
    durations = _mapping(identity["policy_durations"], "topology policy durations")
    expected_duration_fields = set(cast(Mapping[str, Any], topology["policy"])) - {
        "replica_count",
        "observation_quorum",
    }
    if set(durations) != expected_duration_fields or any(
        durations[name] != cast(Mapping[str, Any], topology["policy"])[name]
        for name in durations
    ):
        raise ContractError("topology identity policy durations differ from canonical topology")
    return identity


class MutationLedger:
    """Fail-closed record of the acceptance identity's narrow mutation surface."""

    def __init__(self, *, session_deny: bool):
        self.session_deny = session_deny
        self.route_calls = 0
        self.advertisement_calls = 0
        self.denied_attempts: list[str] = []
        self.allowed_fault_calls: list[str] = []
        self.workload_remote_calls = 0
        self.target_remote_calls = 0
        self.router_remote_calls = 0
        self.actor_validations: list[dict[str, str]] = []

    def aws(self, action: str) -> None:
        normalized = action.lower()
        if normalized in {
            "ec2:associateroutetable",
            "ec2:createroute",
            "ec2:deleteroute",
            "ec2:disassociateroutetable",
            "ec2:replaceroute",
            "ec2:replaceroutetableassociation",
        }:
            self.route_calls += 1
            self.denied_attempts.append(action)
            raise MutationDenied("the protected runner cannot directly mutate EC2 routes")
        if normalized in {"ec2:stopinstances", "ec2:startinstances"}:
            self.allowed_fault_calls.append(action)

    def tailnet(self, action: str) -> None:
        normalized = action.lower()
        if "route" in normalized or "advert" in normalized or "preference" in normalized:
            self.advertisement_calls += 1
            self.denied_attempts.append(action)
            raise MutationDenied("the protected runner cannot mutate Tailnet advertisements or routes")

    def remote(self, role: str) -> None:
        if role == "workload":
            self.workload_remote_calls += 1
            return
        if role == "target":
            self.target_remote_calls += 1
        elif role == "router":
            self.router_remote_calls += 1
        raise MutationDenied("remote execution is permitted only on dedicated workload instances")

    def actor(
        self,
        *,
        operation: str,
        actor_type: str,
        actor_id: str,
        instance_id: str,
        region: str,
        identity_sha256: str,
    ) -> None:
        self.actor_validations.append(
            {
                "operation": operation,
                "actor_type": actor_type,
                "actor_id": actor_id,
                "instance_id": instance_id,
                "region": region,
                "identity_sha256": identity_sha256,
            }
        )

    def evidence(self, identity: Mapping[str, str]) -> dict[str, Any]:
        account_id = _string(identity.get("account_id"), "runner account", pattern=re.compile(r"[0-9]{12}"))
        principal_arn = _string(identity.get("principal_arn"), "runner principal")
        session_name = _string(identity.get("session_name"), "runner session")
        return {
            "runner_identity": {
                "account_id_sha256": hash_identity(account_id),
                "principal_arn_sha256": hash_identity(principal_arn),
                "session_name_sha256": hash_identity(session_name),
            },
            "session_explicit_deny": SESSION_ROUTE_DENY_EVIDENCE
            if self.session_deny
            else None,
            "route_mutation_calls": self.route_calls,
            "advertisement_mutation_calls": self.advertisement_calls,
            "denied_attempts": list(self.denied_attempts),
            "allowed_fault_calls": list(self.allowed_fault_calls),
            "remote_execution": {
                "workload_calls": self.workload_remote_calls,
                "target_calls": self.target_remote_calls,
                "router_calls": self.router_remote_calls,
            },
            "actor_validations": copy.deepcopy(self.actor_validations),
        }


class ProductionAdapter(Protocol):
    ledger: MutationLedger

    def conformance_capabilities(self) -> Mapping[str, bool]: ...

    def acquire_backend_claim(self) -> Mapping[str, Any]: ...

    def prepare(self) -> Mapping[str, Any]: ...

    def deploy_appliance(self) -> Mapping[str, Any]: ...

    def prepare_controller(self) -> Mapping[str, Any]: ...

    def deploy_controller(self, mode: str) -> Mapping[str, Any]: ...

    def wait_observation(
        self, stage: str, context: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]: ...

    def select_domain(self, observations: Sequence[Mapping[str, Any]]) -> Mapping[str, str]: ...

    def start_established_flows(self, selection: Mapping[str, str]) -> Mapping[str, Any]: ...

    def inject_router_failure(self, selection: Mapping[str, str]) -> Mapping[str, Any]: ...

    def probe_fresh_flows(
        self,
        stage: str,
        selection: Mapping[str, str],
        context: Mapping[str, str],
    ) -> Sequence[Mapping[str, Any]]: ...

    def inject_leader_failure(
        self, selection: Mapping[str, str], observation: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...

    def restore_router(self, fault: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def finish_established_flows(
        self, handle: Mapping[str, Any], context: Mapping[str, str]
    ) -> Sequence[Mapping[str, Any]]: ...

    def observe_stale_fence_rejection(
        self,
        selection: Mapping[str, str],
        leader_fault: Mapping[str, Any],
        observation: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def observe_ambiguous_settlement(
        self, selection: Mapping[str, str], observation: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...

    def restore_faults_for_cleanup(self) -> Mapping[str, Any]: ...

    def quiesce_controller(
        self, active_attempted: bool, active_succeeded: bool
    ) -> Mapping[str, Any]: ...

    def destroy_controller(self) -> Mapping[str, Any]: ...

    def delete_controller_material(self) -> Mapping[str, Any]: ...

    def destroy_appliance(self) -> Mapping[str, Any]: ...

    def cleanup_tailnet(self) -> Mapping[str, Any]: ...

    def finalize_backend(self) -> Mapping[str, Any]: ...

    def audit_residuals(self) -> Sequence[Mapping[str, Any]]: ...


def validate_observation(value: Any, *, expected_stage: str | None = None) -> dict[str, Any]:
    observation = _mapping(value, "controller observation")
    fields = {
        "stage",
        "captured_at",
        "domain_id",
        "preferred_owner",
        "dynamodb",
        "controller_endpoints",
        "tailnet",
        "aws_route_table",
        "aws_routes",
        "route_agreement",
    }
    _exact_keys(observation, fields, "controller observation")
    stage = _string(observation["stage"], "observation stage")
    if stage not in STAGES or expected_stage is not None and stage != expected_stage:
        raise EvidenceError("controller observation stage is invalid")
    canonical_timestamp(observation["captured_at"], "observation captured_at")
    _string(observation["domain_id"], "observation domain ID", pattern=_ID_RE)
    _string(observation["preferred_owner"], "observation preferred owner", pattern=_ID_RE)

    durable = _mapping(observation["dynamodb"], "observation DynamoDB")
    _exact_keys(
        durable,
        {
            "present",
            "phase",
            "stable_owner",
            "observed_owner",
            "lease_holder",
            "fence_term",
            "revision",
            "cooldown_until",
            "lease_record_version",
            "lease_renewed_at",
            "lease_expires_at",
            "owner_observed_at",
            "last_transition_at",
            "error_code",
            "error_ambiguous",
            "transaction",
        },
        "observation DynamoDB",
    )
    present = _boolean(durable["present"], "DynamoDB present")
    phase = _optional_string(durable["phase"], "DynamoDB phase")
    if phase is not None and phase not in PHASES:
        raise EvidenceError("DynamoDB phase is invalid")
    for name in ("stable_owner", "observed_owner", "lease_holder"):
        _optional_string(durable[name], f"DynamoDB {name}", pattern=_ID_RE)
    _integer(durable["fence_term"], "DynamoDB fence term")
    _integer(durable["revision"], "DynamoDB revision")
    _integer(durable["lease_record_version"], "DynamoDB lease record version")
    for name in (
        "cooldown_until",
        "lease_renewed_at",
        "lease_expires_at",
        "owner_observed_at",
        "last_transition_at",
    ):
        if durable[name] is not None:
            canonical_timestamp(durable[name], f"DynamoDB {name}")
    _optional_string(durable["error_code"], "DynamoDB error code", pattern=_ID_RE)
    _boolean(durable["error_ambiguous"], "DynamoDB error ambiguous")
    transaction = durable["transaction"]
    if transaction is not None:
        transaction = _mapping(transaction, "DynamoDB transaction")
        _exact_keys(
            transaction,
            {
                "transaction_id_sha256",
                "fence_term",
                "desired_owner",
                "desired_eni_id",
                "before_sha256",
                "progress",
            },
            "DynamoDB transaction",
        )
        _string(transaction["transaction_id_sha256"], "transaction ID SHA", pattern=_SHA_RE)
        _integer(transaction["fence_term"], "transaction fence term", 1)
        _string(transaction["desired_owner"], "transaction desired owner", pattern=_ID_RE)
        _string(transaction["desired_eni_id"], "transaction desired ENI", pattern=_ENI_RE)
        _string(transaction["before_sha256"], "transaction before SHA", pattern=_SHA_RE)
        if not isinstance(transaction["progress"], list) or not transaction["progress"]:
            raise EvidenceError("transaction progress must be a nonempty list")
        progress_prefixes: set[str] = set()
        for index, raw_progress in enumerate(transaction["progress"]):
            progress = _mapping(raw_progress, f"transaction progress {index}")
            _exact_keys(
                progress,
                {
                    "destination_prefix",
                    "attempted",
                    "completed",
                    "observed_eni_id",
                    "ambiguous",
                },
                f"transaction progress {index}",
            )
            prefix = _validate_prefix(
                progress["destination_prefix"], f"transaction progress {index} destination"
            )
            if prefix in progress_prefixes:
                raise EvidenceError("transaction progress destinations must be unique")
            progress_prefixes.add(prefix)
            attempted = _boolean(progress["attempted"], "transaction progress attempted")
            completed = _boolean(progress["completed"], "transaction progress completed")
            if completed and not attempted:
                raise EvidenceError("completed transaction progress was never attempted")
            _optional_string(
                progress["observed_eni_id"],
                "transaction progress observed ENI",
                pattern=_ENI_RE,
            )
            _boolean(progress["ambiguous"], "transaction progress ambiguous")
    if not present and any(
        durable[name] is not None
        for name in (
            "phase",
            "stable_owner",
            "observed_owner",
            "lease_holder",
            "cooldown_until",
            "lease_renewed_at",
            "lease_expires_at",
            "owner_observed_at",
            "last_transition_at",
            "error_code",
            "transaction",
        )
    ):
        raise EvidenceError("absent DynamoDB state contains durable values")
    if not present and (
        durable["fence_term"] != 0
        or durable["revision"] != 0
        or durable["lease_record_version"] != 0
        or durable["error_ambiguous"] is not False
    ):
        raise EvidenceError("absent DynamoDB state contains nonzero durable counters")

    endpoints = observation["controller_endpoints"]
    if not isinstance(endpoints, list) or len(endpoints) != 3:
        raise EvidenceError("observation must contain exactly three controller endpoints")
    endpoint_ids: set[str] = set()
    for index, raw_endpoint in enumerate(endpoints):
        endpoint = _mapping(raw_endpoint, f"controller endpoint {index}")
        _exact_keys(
            endpoint,
            {
                "controller_id",
                "instance_id",
                "private_ip",
                "health_status",
                "ready_status",
                "ready_reason",
                "mode",
                "role",
                "phase",
                "fence_term",
                "metrics_sha256",
            },
            f"controller endpoint {index}",
        )
        controller_id = _string(endpoint["controller_id"], "endpoint controller ID", pattern=_ID_RE)
        if controller_id in endpoint_ids:
            raise EvidenceError("controller endpoint IDs must be unique")
        endpoint_ids.add(controller_id)
        _string(endpoint["instance_id"], "endpoint controller instance", pattern=_INSTANCE_RE)
        try:
            endpoint_address = ipaddress.ip_address(
                _string(endpoint["private_ip"], "endpoint controller private IP")
            )
        except ValueError as error:
            raise EvidenceError("endpoint controller private IP is invalid") from error
        if endpoint_address.version != 4:
            raise EvidenceError("endpoint controller private IP must be IPv4")
        if _integer(endpoint["health_status"], "health status", 0, 599) not in {0, 200}:
            raise EvidenceError("controller health status must be 0 or 200")
        if _integer(endpoint["ready_status"], "ready status", 0, 599) not in {0, 200, 503}:
            raise EvidenceError("controller ready status must be 0, 200, or 503")
        for name in ("ready_reason", "mode", "role", "phase"):
            _string(endpoint[name], f"endpoint {name}", maximum=128)
        _integer(endpoint["fence_term"], "endpoint fence term")
        _string(endpoint["metrics_sha256"], "endpoint metrics SHA", pattern=_SHA_RE)

    tailnet = _mapping(observation["tailnet"], "observation Tailnet")
    _exact_keys(
        tailnet,
        {
            "owner_router_id",
            "owner_node_sha256",
            "observer_quorum",
            "agreement",
            "contributors",
            "failed_router_online",
        },
        "observation Tailnet",
    )
    _optional_string(tailnet["owner_router_id"], "Tailnet owner", pattern=_ID_RE)
    _optional_string(tailnet["owner_node_sha256"], "Tailnet node SHA", pattern=_SHA_RE)
    _integer(tailnet["observer_quorum"], "Tailnet observer quorum", 0, 31)
    _boolean(tailnet["agreement"], "Tailnet observer agreement")
    if not isinstance(tailnet["contributors"], list) or len(tailnet["contributors"]) > 31:
        raise EvidenceError("Tailnet contributors must be a bounded list")
    contributor_ids: set[str] = set()
    for index, raw_contributor in enumerate(tailnet["contributors"]):
        contributor = _mapping(raw_contributor, f"Tailnet contributor {index}")
        _exact_keys(
            contributor,
            {
                "controller_id",
                "sequence",
                "captured_at",
                "expires_at",
                "fresh",
                "backend_healthy",
                "sole_primary",
                "owner_healthy",
                "owner_node_sha256",
                "owner_since",
            },
            f"Tailnet contributor {index}",
        )
        controller_id = _string(
            contributor["controller_id"], "Tailnet contributor controller", pattern=_ID_RE
        )
        if controller_id in contributor_ids:
            raise EvidenceError("Tailnet contributor controller IDs must be distinct")
        contributor_ids.add(controller_id)
        _integer(contributor["sequence"], "Tailnet contributor sequence", 1)
        captured = parse_timestamp(contributor["captured_at"], "Tailnet contributor captured_at")
        expires = parse_timestamp(contributor["expires_at"], "Tailnet contributor expires_at")
        if expires <= captured:
            raise EvidenceError("Tailnet contributor expires before capture")
        for name in ("fresh", "backend_healthy", "sole_primary", "owner_healthy"):
            _boolean(contributor[name], f"Tailnet contributor {name}")
        _optional_string(
            contributor["owner_node_sha256"],
            "Tailnet contributor owner SHA",
            pattern=_SHA_RE,
        )
        if contributor["owner_since"] is not None:
            owner_since = parse_timestamp(
                contributor["owner_since"], "Tailnet contributor owner_since"
            )
            if owner_since > captured:
                raise EvidenceError("Tailnet contributor owner_since follows capture")
    if tailnet["failed_router_online"] is not None:
        _boolean(tailnet["failed_router_online"], "Tailnet failed-router online")

    route_table = _mapping(observation["aws_route_table"], "observation AWS route table")
    _exact_keys(
        route_table,
        {
            "route_table_id",
            "vpc_id",
            "gwlbe_subnet_id",
            "route_table_association_id",
            "explicit_association_count",
            "association_state",
            "stable_read_count",
            "snapshot_sha256",
        },
        "observation AWS route table",
    )
    _string(route_table["route_table_id"], "observed route table ID", pattern=_ROUTE_TABLE_RE)
    _string(route_table["vpc_id"], "observed route table VPC", pattern=_VPC_RE)
    _string(route_table["gwlbe_subnet_id"], "observed GWLBE subnet", pattern=_SUBNET_RE)
    _string(
        route_table["route_table_association_id"],
        "observed route association",
        pattern=_ASSOCIATION_RE,
    )
    _integer(route_table["explicit_association_count"], "explicit association count", 0, 32)
    if route_table["association_state"] != "associated":
        raise EvidenceError("observed route-table association is not associated")
    _integer(route_table["stable_read_count"], "stable route read count", 1, 32)
    _string(route_table["snapshot_sha256"], "route snapshot SHA", pattern=_SHA_RE)

    routes = observation["aws_routes"]
    if not isinstance(routes, list) or not routes:
        raise EvidenceError("observation AWS routes must be nonempty")
    destinations: set[str] = set()
    for index, raw_route in enumerate(routes):
        route = _mapping(raw_route, f"observation AWS route {index}")
        _exact_keys(
            route,
            {"destination_prefix", "target_router_id", "target_eni_id", "state", "origin"},
            f"observation AWS route {index}",
        )
        destination = _validate_prefix(route["destination_prefix"], "route destination")
        if destination in destinations:
            raise EvidenceError("observation AWS route destinations must be unique")
        destinations.add(destination)
        _optional_string(route["target_router_id"], "route target router", pattern=_ID_RE)
        _string(route["target_eni_id"], "route target ENI", pattern=_ENI_RE)
        if route["state"] != "active" or route["origin"] != "CreateRoute":
            raise EvidenceError("observed controller routes must be active CreateRoute routes")
    expected_snapshot = route_snapshot_sha256(route_table, routes)
    if route_table["snapshot_sha256"] != expected_snapshot:
        raise EvidenceError("route snapshot SHA does not bind the retained authoritative read")
    _boolean(observation["route_agreement"], "route agreement")
    return observation


def validate_flow(value: Any) -> dict[str, Any]:
    flow = _mapping(value, "fresh flow evidence")
    _exact_keys(
        flow,
        {
            "stage",
            "protocol",
            "attempts",
            "success",
            "flow_id_sha256",
            "connection_id_sha256",
            "started_at",
            "event_at",
            "convergence_at",
            "completed_at",
            "recovery_milliseconds",
            "source_workload",
            "destination_workload",
            "source_instance_id",
            "destination_instance_id",
            "source_port",
            "responder_acknowledged",
            "messages_sent",
            "messages_received",
            "loss_basis_points",
            "latency_milliseconds",
        },
        "fresh flow evidence",
    )
    if flow["stage"] not in {"router-failover", "failback-stable"}:
        raise EvidenceError("fresh flow stage is invalid")
    if flow["protocol"] not in {"tcp", "udp"}:
        raise EvidenceError("fresh flow protocol is invalid")
    _integer(flow["attempts"], "fresh flow attempts", 1, 128)
    _boolean(flow["success"], "fresh flow success")
    _string(flow["flow_id_sha256"], "fresh flow ID SHA", pattern=_SHA_RE)
    _string(flow["connection_id_sha256"], "fresh connection ID SHA", pattern=_SHA_RE)
    event_at = parse_timestamp(flow["event_at"], "fresh flow event_at")
    convergence_at = parse_timestamp(flow["convergence_at"], "fresh flow convergence_at")
    started_at = parse_timestamp(flow["started_at"], "fresh flow started_at")
    completed_at = parse_timestamp(flow["completed_at"], "fresh flow completed_at")
    if not event_at <= convergence_at <= started_at <= completed_at:
        raise EvidenceError("fresh flow timestamps do not follow event and convergence")
    recovery_milliseconds = _integer(
        flow["recovery_milliseconds"], "fresh flow recovery milliseconds", 0, 86_400_000
    )
    if recovery_milliseconds != int((completed_at - event_at).total_seconds() * 1000):
        raise EvidenceError("fresh flow recovery measurement differs from its timestamps")
    for name in ("source_workload", "destination_workload"):
        _string(flow[name], f"fresh flow {name}", pattern=_ID_RE)
    for name in ("source_instance_id", "destination_instance_id"):
        _string(flow[name], f"fresh flow {name}", pattern=_INSTANCE_RE)
    _integer(flow["source_port"], "fresh flow source port", 1024, 65535)
    _boolean(flow["responder_acknowledged"], "fresh flow responder acknowledgement")
    sent = _integer(flow["messages_sent"], "fresh flow sent messages", 1, 128)
    received = _integer(flow["messages_received"], "fresh flow received messages", 0, sent)
    loss = _integer(flow["loss_basis_points"], "fresh flow loss basis points", 0, 10_000)
    if loss != (sent - received) * 10_000 // sent:
        raise EvidenceError("fresh flow loss differs from sent and received messages")
    _integer(flow["latency_milliseconds"], "fresh flow latency milliseconds", 0, 60_000)
    return flow


def parse_established_agent_output(
    value: Any,
    *,
    protocol: str,
    flow_id: str,
    source_ip: str,
    source_port: int,
    expected_markers: int,
    sampled_monotonic_ns: int,
    convergence_monotonic_ns: int,
) -> dict[str, Any]:
    """Validate the agent's bounded stream summary without using SSM status."""
    if protocol not in {"tcp", "udp"}:
        raise ContractError("established protocol is invalid")
    flow_id = _string(flow_id, "established flow ID", pattern=_ID_RE)
    source_ip = _string(source_ip, "established source IP", maximum=64)
    source_port = _integer(source_port, "established source port", 1024, 65535)
    sampled_monotonic_ns = _integer(
        sampled_monotonic_ns, "established sample monotonic time", 1
    )
    convergence_monotonic_ns = _integer(
        convergence_monotonic_ns, "established convergence monotonic time", 1
    )
    if convergence_monotonic_ns < sampled_monotonic_ns:
        raise ContractError("established convergence sample precedes the fault barrier")
    output = _mapping(value, f"established {protocol} agent output")
    _exact_keys(
        output,
        {
            "schema",
            "operation",
            "protocol",
            "success",
            "outcome",
            "error_category",
            "flow_id",
            "connection_id",
            "local_ip",
            "source_port",
            "socket_count",
            "expected_markers",
            "sequences",
            "timing",
        },
        f"established {protocol} agent output",
    )
    expected_markers = _integer(
        expected_markers,
        "expected established markers",
        2,
        ESTABLISHED_MAX_MARKERS,
    )
    schema = _integer(output["schema"], "established agent schema", 1, 16)
    operation = _string(output["operation"], "established agent operation", maximum=32)
    output_protocol = _string(
        output["protocol"], "established agent protocol", maximum=8
    )
    output_flow_id = _string(output["flow_id"], "established agent flow ID", pattern=_ID_RE)
    output_connection_id = _string(
        output["connection_id"], "established agent connection ID", maximum=128
    )
    output_local_ip = _string(output["local_ip"], "established agent local IP", maximum=64)
    output_source_port = _integer(
        output["source_port"], "established agent source port", 1024, 65535
    )
    socket_count = _integer(output["socket_count"], "established agent socket count", 1, 8)
    output_expected = _integer(
        output["expected_markers"],
        "established agent expected markers",
        2,
        ESTABLISHED_MAX_MARKERS,
    )
    if (
        schema != ESTABLISHED_AGENT_SCHEMA
        or operation != "stream"
        or output_protocol != protocol
        or output_flow_id != flow_id
        or output_connection_id != f"{flow_id}:c0001"
        or output_local_ip != source_ip
        or output_source_port != source_port
        or socket_count != 1
        or output_expected != expected_markers
    ):
        raise ContractError("established agent output differs from its launched one-socket flow")
    success = _boolean(output["success"], "established agent success")
    outcome = _string(output["outcome"], "established agent outcome", maximum=32)
    error_category = output["error_category"]
    if error_category is not None:
        error_category = _string(
            error_category, "established agent error category", pattern=_ID_RE, maximum=32
        )

    sequences = _mapping(output["sequences"], "established agent sequences")
    _exact_keys(sequences, {"attempted", "acknowledged"}, "established agent sequences")

    def sequence_range(name: str, maximum: int) -> tuple[int, int, int]:
        sequence = _mapping(sequences[name], f"established {name} sequence")
        _exact_keys(sequence, {"count", "first", "last"}, f"established {name} sequence")
        count = _integer(sequence["count"], f"established {name} count", 1, maximum)
        first = _integer(sequence["first"], f"established {name} first", 0, maximum - 1)
        last = _integer(sequence["last"], f"established {name} last", 0, maximum - 1)
        if first != 0 or last != count - 1:
            raise ContractError(f"established {name} sequences are not contiguous from zero")
        return count, first, last

    attempted, _attempted_first, attempted_last = sequence_range(
        "attempted", expected_markers
    )
    acknowledged, acknowledged_first, acknowledged_last = sequence_range(
        "acknowledged", attempted
    )
    if acknowledged > attempted:
        raise ContractError("established acknowledgements exceed attempted markers")

    timing = _mapping(output["timing"], "established agent timing")
    _exact_keys(
        timing,
        {"first_acknowledged", "last_acknowledged", "last_attempted"},
        "established agent timing",
    )

    def timing_values(name: str, length: int) -> list[int]:
        values = timing[name]
        if not isinstance(values, list) or len(values) != length:
            raise ContractError(f"established {name} timing has the wrong shape")
        return [
            _integer(item, f"established {name} timing {index}", 0 if index == 0 else 1)
            for index, item in enumerate(values)
        ]

    first_ack = timing_values("first_acknowledged", 3)
    last_ack = timing_values("last_acknowledged", 3)
    last_attempt = timing_values("last_attempted", 2)
    if (
        first_ack[0] != acknowledged_first
        or last_ack[0] != acknowledged_last
        or last_attempt[0] != attempted_last
        or first_ack[1] > first_ack[2]
        or last_ack[1] > last_ack[2]
        or acknowledged > 1
        and (last_ack[1] <= first_ack[1] or last_ack[2] <= first_ack[2])
        or acknowledged == 1
        and last_ack != first_ack
        or attempted == acknowledged
        and last_attempt != last_ack[:2]
        or attempted > acknowledged
        and last_attempt[1] <= last_ack[2]
    ):
        raise ContractError("established compact marker timing or sequence bounds are invalid")
    if first_ack[2] > sampled_monotonic_ns:
        raise ContractError("established flow lacks an acknowledgement before the fault barrier")

    if outcome == "survived":
        if (
            success is not True
            or error_category is not None
            or attempted != expected_markers
            or acknowledged != expected_markers
        ):
            raise ContractError("survived established output is incomplete or contradictory")
    elif outcome == "reset":
        if success is not False or error_category not in RESET_ERROR_CATEGORIES:
            raise ContractError("reset established output has an invalid error category")
    elif outcome == "timed-out":
        if success is not False or error_category not in TIMEOUT_ERROR_CATEGORIES:
            raise ContractError("timed-out established output has an invalid error category")
    else:
        raise ContractError("established agent output has an unsupported outcome")
    if outcome != "survived" and acknowledged >= expected_markers:
        raise ContractError("interrupted established output is not a partial result")

    post_convergence = (
        acknowledged_last if last_ack[1] >= convergence_monotonic_ns else None
    )
    if outcome == "survived" and (
        post_convergence is None or post_convergence <= acknowledged_first
    ):
        raise ContractError("survived established flow lacks a post-convergence acknowledgement")
    return {
        "outcome": outcome,
        "error_category": error_category,
        "expected_markers": expected_markers,
        "attempted_markers": attempted,
        "acknowledged_markers": acknowledged,
        "loss_basis_points": (attempted - acknowledged) * 10_000 // attempted,
        "pre_fault_acknowledged_sequence": acknowledged_first,
        "post_convergence_acknowledged_sequence": post_convergence,
        "one_socket": True,
        "agent_output_verified": True,
    }


def validate_established_flow(value: Any) -> dict[str, Any]:
    flow = _mapping(value, "established flow evidence")
    _exact_keys(
        flow,
        {
            "protocol",
            "outcome",
            "flow_id_sha256",
            "connection_id_sha256",
            "source_workload",
            "destination_workload",
            "source_instance_id",
            "destination_instance_id",
            "source_port",
            "sampled_at",
            "fault_injected_at",
            "convergence_at",
            "classified_at",
            "error_category",
            "expected_markers",
            "attempted_markers",
            "acknowledged_markers",
            "loss_basis_points",
            "pre_fault_acknowledged_sequence",
            "post_convergence_acknowledged_sequence",
            "one_socket",
            "agent_output_verified",
        },
        "established flow evidence",
    )
    if flow["protocol"] not in {"tcp", "udp"} or flow["outcome"] not in OUTCOMES:
        raise EvidenceError("established flow classification is invalid")
    for name in ("flow_id_sha256", "connection_id_sha256"):
        _string(flow[name], f"established flow {name}", pattern=_SHA_RE)
    for name in ("source_workload", "destination_workload"):
        _string(flow[name], f"established flow {name}", pattern=_ID_RE)
    for name in ("source_instance_id", "destination_instance_id"):
        _string(flow[name], f"established flow {name}", pattern=_INSTANCE_RE)
    _integer(flow["source_port"], "established flow source port", 1024, 65535)
    sampled_at = parse_timestamp(flow["sampled_at"], "established flow sampled_at")
    fault_at = parse_timestamp(flow["fault_injected_at"], "established flow fault_at")
    convergence_at = parse_timestamp(flow["convergence_at"], "established flow convergence_at")
    classified_at = parse_timestamp(flow["classified_at"], "established flow classified_at")
    if not sampled_at <= fault_at <= convergence_at <= classified_at:
        raise EvidenceError("established flow timestamps do not span the fault and convergence")
    expected = _integer(
        flow["expected_markers"],
        "established expected markers",
        2,
        ESTABLISHED_MAX_MARKERS,
    )
    attempted = _integer(
        flow["attempted_markers"], "established attempted markers", 1, expected
    )
    acknowledged = _integer(
        flow["acknowledged_markers"],
        "established acknowledged markers",
        1,
        attempted,
    )
    loss = _integer(flow["loss_basis_points"], "established loss basis points", 0, 10_000)
    if loss != (attempted - acknowledged) * 10_000 // attempted:
        raise EvidenceError("established flow loss differs from attempted acknowledgements")
    before = _integer(
        flow["pre_fault_acknowledged_sequence"],
        "established pre-fault acknowledged sequence",
        0,
        acknowledged - 1,
    )
    after = flow["post_convergence_acknowledged_sequence"]
    if after is not None:
        after = _integer(
            after, "established post-convergence sequence", 0, acknowledged - 1
        )
    _boolean(flow["one_socket"], "established one-socket evidence")
    _boolean(flow["agent_output_verified"], "established agent output verification")
    error_category = _optional_string(
        flow["error_category"], "established flow error category", pattern=_ID_RE
    )
    if flow["outcome"] == "survived" and (
        error_category is not None
        or after is None
        or after <= before
        or attempted != expected
        or acknowledged != expected
        or loss != 0
    ):
        raise EvidenceError("survived established flow lacks post-convergence lossless markers")
    if flow["outcome"] == "reset" and error_category not in RESET_ERROR_CATEGORIES:
        raise EvidenceError("reset established flow lacks a bounded reset category")
    if flow["outcome"] == "timed-out" and error_category not in TIMEOUT_ERROR_CATEGORIES:
        raise EvidenceError("timed-out established flow lacks a bounded timeout category")
    if flow["outcome"] != "survived" and acknowledged >= expected:
        raise EvidenceError("interrupted established flow lacks bounded partial marker evidence")
    return flow


def validate_actor_summary(value: Any) -> dict[str, Any]:
    actors = _mapping(value, "runtime actor evidence")
    _exact_keys(actors, {"instances"}, "runtime actor evidence")
    instances = actors["instances"]
    if not isinstance(instances, list) or not instances:
        raise EvidenceError("runtime actor evidence must contain instances")
    actor_keys: set[tuple[str, str]] = set()
    instance_ids: set[str] = set()
    private_identities: set[tuple[str, str]] = set()
    normalized: list[dict[str, Any]] = []
    for index, raw_actor in enumerate(instances):
        actor = _mapping(raw_actor, f"runtime actor {index}")
        _exact_keys(
            actor,
            {
                "actor_type",
                "actor_id",
                "instance_id",
                "region",
                "vpc_id",
                "subnet_id",
                "availability_zone",
                "private_ip",
            },
            f"runtime actor {index}",
        )
        actor_type = _string(actor["actor_type"], "runtime actor type")
        if actor_type not in {"controller", "router", "workload"}:
            raise EvidenceError("runtime actor type is unsupported")
        actor_id = _string(actor["actor_id"], "runtime actor ID", pattern=_ID_RE)
        instance_id = _string(
            actor["instance_id"], "runtime actor instance", pattern=_INSTANCE_RE
        )
        _string(actor["region"], "runtime actor region", pattern=_REGION_RE)
        _string(actor["vpc_id"], "runtime actor VPC", pattern=_VPC_RE)
        _string(actor["subnet_id"], "runtime actor subnet", pattern=_SUBNET_RE)
        region = str(actor["region"])
        _string(
            actor["availability_zone"],
            "runtime actor availability zone",
            pattern=re.compile(re.escape(region) + r"[a-z]"),
        )
        if actor["private_ip"] is not None:
            try:
                address = ipaddress.ip_address(
                    _string(actor["private_ip"], "runtime actor private IP")
                )
            except ValueError as error:
                raise EvidenceError("runtime actor private IP is invalid") from error
            if address.version != 4:
                raise EvidenceError("runtime actor private IP must be IPv4")
        if (
            actor_type == "router"
            and actor["private_ip"] is not None
            or actor_type != "router"
            and actor["private_ip"] is None
        ):
            raise EvidenceError(
                "runtime actor private-IP shape differs from its actor type"
            )
        if actor["private_ip"] is not None:
            private_identity = (str(actor["vpc_id"]), str(actor["private_ip"]))
            if private_identity in private_identities:
                raise EvidenceError("runtime actor private identities must be unique")
            private_identities.add(private_identity)
        actor_key = (actor_type, actor_id)
        if actor_key in actor_keys or instance_id in instance_ids:
            raise EvidenceError("runtime actor identities must be globally unique")
        actor_keys.add(actor_key)
        instance_ids.add(instance_id)
        normalized.append(actor)
    if normalized != sorted(
        normalized,
        key=lambda actor: (str(actor["actor_type"]), str(actor["actor_id"])),
    ):
        raise EvidenceError("runtime actor evidence must be canonically ordered")
    return actors


def validate_evidence(value: Any) -> dict[str, Any]:
    evidence = _mapping(value, "production controller evidence")
    fields = {
        "schema",
        "kind",
        "run_id",
        "status",
        "started_at",
        "completed_at",
        "configuration_sha256",
        "state",
        "topology",
        "actors",
        "artifacts",
        "secret_references",
        "rollout",
        "faults",
        "observations",
        "fresh_flows",
        "established_flows",
        "control_plane",
        "mutation_audit",
        "cleanup",
        "failure",
    }
    _exact_keys(evidence, fields, "production controller evidence")
    if evidence["schema"] != EVIDENCE_SCHEMA or evidence["kind"] != EVIDENCE_KIND:
        raise EvidenceError("evidence schema or kind is unsupported")
    _string(evidence["run_id"], "evidence run ID", pattern=_RUN_RE)
    if evidence["status"] not in {"passed", "failed"}:
        raise EvidenceError("evidence status is invalid")
    if parse_timestamp(evidence["completed_at"], "evidence completed_at") < parse_timestamp(
        evidence["started_at"], "evidence started_at"
    ):
        raise EvidenceError("evidence completed before it started")
    _string(evidence["configuration_sha256"], "configuration SHA", pattern=_SHA_RE)

    state = _mapping(evidence["state"], "evidence state")
    _exact_keys(
        state,
        {"appliance_key_sha256", "controller_key_sha256", "distinct"},
        "evidence state",
    )
    appliance_key = _string(state["appliance_key_sha256"], "appliance state SHA", pattern=_SHA_RE)
    controller_key = _string(state["controller_key_sha256"], "controller state SHA", pattern=_SHA_RE)
    if state["distinct"] is not True or appliance_key == controller_key:
        raise EvidenceError("evidence does not prove separate Terraform state keys")

    for nullable_name in ("topology", "actors", "artifacts"):
        if evidence[nullable_name] is not None and not isinstance(evidence[nullable_name], Mapping):
            raise EvidenceError(f"evidence {nullable_name} must be an object or null")
    if evidence["actors"] is not None:
        validate_actor_summary(evidence["actors"])
    if evidence["topology"] is not None:
        topology = _mapping(evidence["topology"], "evidence topology")
        _exact_keys(
            topology,
            {
                "schema_version",
                "sha256",
                "source_output_sha256",
                "controller_ids",
                "domain_ids",
                "policy",
                "gwlbe_authority",
            },
            "evidence topology",
        )
        if topology["schema_version"] != TOPOLOGY_SCHEMA:
            raise EvidenceError("evidence topology schema is invalid")
        _string(topology["sha256"], "evidence topology SHA", pattern=_SHA_RE)
        _string(topology["source_output_sha256"], "source output SHA", pattern=_SHA_RE)
        _string_list(
            topology["controller_ids"],
            "evidence topology controllers",
            minimum=3,
            pattern=_ID_RE,
            sorted_required=True,
        )
        if len(topology["controller_ids"]) != 3:
            raise EvidenceError("evidence topology must identify exactly three controllers")
        policy = _mapping(topology["policy"], "evidence topology policy")
        _exact_keys(
            policy,
            {
                "observation_quorum",
                "observation_freshness_milliseconds",
                "lease_renew_interval_milliseconds",
                "failback_stability_milliseconds",
                "cooldown_milliseconds",
            },
            "evidence topology policy",
        )
        _integer(policy["observation_quorum"], "evidence observation quorum", 2, 31)
        for name in (
            "observation_freshness_milliseconds",
            "lease_renew_interval_milliseconds",
            "failback_stability_milliseconds",
            "cooldown_milliseconds",
        ):
            _integer(policy[name], f"evidence topology policy {name}", 100, 86_400_000)
        domain_ids = _string_list(
            topology["domain_ids"], "evidence topology domains", minimum=1, pattern=_ID_RE, sorted_required=True
        )
        authority = topology["gwlbe_authority"]
        if not isinstance(authority, list) or len(authority) != len(domain_ids):
            raise EvidenceError("evidence GWLBE authority must cover every domain")
        association_ids: set[str] = set()
        subnet_ids: set[str] = set()
        route_table_ids: set[str] = set()
        authority_domain_ids: set[str] = set()
        for index, raw_domain in enumerate(authority):
            domain = _mapping(raw_domain, f"evidence GWLBE authority {index}")
            _exact_keys(
                domain,
                {
                    "domain_id",
                    "site_id",
                    "region",
                    "vpc_id",
                    "route_table_id",
                    "gwlbe_subnet_id",
                    "route_table_association_id",
                    "source_prefix",
                    "remote_prefixes",
                    "preferred_owner",
                    "eligible_routers",
                },
                f"evidence GWLBE authority {index}",
            )
            authority_domain_ids.add(
                _string(domain["domain_id"], "authority domain", pattern=_ID_RE)
            )
            route_table_ids.add(
                _string(
                    domain["route_table_id"],
                    "authority route table",
                    pattern=_ROUTE_TABLE_RE,
                )
            )
            subnet_ids.add(_string(domain["gwlbe_subnet_id"], "authority GWLBE subnet", pattern=_SUBNET_RE))
            association_ids.add(
                _string(
                    domain["route_table_association_id"],
                    "authority route association",
                    pattern=_ASSOCIATION_RE,
                )
            )
            _string(domain["site_id"], "authority site", pattern=_ID_RE)
            _string(domain["region"], "authority region", pattern=_REGION_RE)
            _string(domain["vpc_id"], "authority VPC", pattern=_VPC_RE)
            _validate_prefix(domain["source_prefix"], "authority source prefix")
            _string_list(
                domain["remote_prefixes"],
                "authority remote prefixes",
                minimum=1,
                sorted_required=True,
            )
            for prefix in domain["remote_prefixes"]:
                _validate_prefix(prefix, "authority remote prefix")
            preferred_owner = _string(
                domain["preferred_owner"], "authority preferred owner", pattern=_ID_RE
            )
            routers = domain["eligible_routers"]
            if not isinstance(routers, list) or len(routers) < 2:
                raise EvidenceError("authority eligible routers must contain at least two entries")
            router_ids: set[str] = set()
            eni_ids: set[str] = set()
            node_hashes: set[str] = set()
            for router_index, raw_router in enumerate(routers):
                router = _mapping(raw_router, f"authority eligible router {router_index}")
                _exact_keys(
                    router,
                    {"router_id", "instance_id", "eni_id", "stable_node_sha256"},
                    f"authority eligible router {router_index}",
                )
                router_ids.add(
                    _string(router["router_id"], "authority eligible router ID", pattern=_ID_RE)
                )
                _string(
                    router["instance_id"],
                    "authority eligible router instance",
                    pattern=_INSTANCE_RE,
                )
                eni_ids.add(
                    _string(router["eni_id"], "authority eligible router ENI", pattern=_ENI_RE)
                )
                node_hashes.add(
                    _string(
                        router["stable_node_sha256"],
                        "authority eligible stable-node SHA",
                        pattern=_SHA_RE,
                    )
                )
            if (
                len(router_ids) != len(routers)
                or len(eni_ids) != len(routers)
                or len(node_hashes) != len(routers)
                or preferred_owner not in router_ids
                or routers != sorted(routers, key=lambda item: str(item["router_id"]))
            ):
                raise EvidenceError("authority eligible router/ENI bindings are not exact")
        if (
            authority_domain_ids != set(domain_ids)
            or len(route_table_ids) != len(authority)
            or len(subnet_ids) != len(authority)
            or len(association_ids) != len(authority)
        ):
            raise EvidenceError(
                "GWLBE domain, route-table, subnet, and association authority must be exact and unique"
            )

    references = _mapping(evidence["secret_references"], "evidence secret references")
    _exact_keys(references, {"value_material_recorded", "parameters"}, "evidence secret references")
    if references["value_material_recorded"] is not False or not isinstance(references["parameters"], list):
        raise EvidenceError("evidence may retain only secret references")
    reference_purposes: set[str] = set()
    reference_names: set[str] = set()
    reference_arns: set[str] = set()
    for index, raw_reference in enumerate(references["parameters"]):
        reference = _mapping(raw_reference, f"secret reference {index}")
        _exact_keys(
            reference,
            {"purpose", "name", "arn", "kms_key_arn_sha256"},
            f"secret reference {index}",
        )
        reference_purposes.add(
            _string(reference["purpose"], "secret reference purpose", pattern=_ID_RE)
        )
        reference_names.add(_string(reference["name"], "secret parameter name"))
        reference_arns.add(_string(reference["arn"], "secret parameter ARN"))
        _string(reference["kms_key_arn_sha256"], "secret KMS ARN SHA", pattern=_SHA_RE)
    if any(
        len(values) != len(references["parameters"])
        for values in (reference_purposes, reference_names, reference_arns)
    ):
        raise EvidenceError("secret references must have unique purposes, names, and ARNs")

    observations = evidence["observations"]
    if not isinstance(observations, list):
        raise EvidenceError("evidence observations must be a list")
    for observation in observations:
        validate_observation(observation)
    flows = evidence["fresh_flows"]
    if not isinstance(flows, list):
        raise EvidenceError("evidence fresh_flows must be a list")
    for flow in flows:
        validate_flow(flow)
    established = evidence["established_flows"]
    if not isinstance(established, list):
        raise EvidenceError("evidence established_flows must be a list")
    for raw_flow in established:
        validate_established_flow(raw_flow)

    control_plane = _mapping(evidence["control_plane"], "evidence control plane")
    _exact_keys(
        control_plane,
        {"stale_fence_rejection", "ambiguous_settlement"},
        "evidence control plane",
    )
    stale = control_plane["stale_fence_rejection"]
    if stale is not None:
        stale = _mapping(stale, "stale-fence rejection evidence")
        _exact_keys(
            stale,
            {
                "domain_id",
                "stale_controller_id",
                "stale_fence",
                "current_fence",
                "observed_at",
                "state_revision_before",
                "state_revision_after",
                "route_snapshot_before_sha256",
                "route_snapshot_after_sha256",
                "stale_write_rejected",
                "stale_route_calls",
            },
            "stale-fence rejection evidence",
        )
        _string(stale["domain_id"], "stale-fence domain", pattern=_ID_RE)
        _string(stale["stale_controller_id"], "stale controller", pattern=_ID_RE)
        _integer(stale["stale_fence"], "stale fence", 1)
        _integer(stale["current_fence"], "current fence", 1)
        canonical_timestamp(stale["observed_at"], "stale-fence observed_at")
        _integer(stale["state_revision_before"], "stale-fence revision before", 1)
        _integer(stale["state_revision_after"], "stale-fence revision after", 1)
        for name in ("route_snapshot_before_sha256", "route_snapshot_after_sha256"):
            _string(stale[name], f"stale-fence {name}", pattern=_SHA_RE)
        _boolean(stale["stale_write_rejected"], "stale write rejected")
        _integer(stale["stale_route_calls"], "stale route calls", 0)

    ambiguous = control_plane["ambiguous_settlement"]
    if ambiguous is not None:
        ambiguous = _mapping(ambiguous, "ambiguous settlement evidence")
        _exact_keys(
            ambiguous,
            {
                "domain_id",
                "transaction_id_sha256",
                "fence_term",
                "destination_prefix",
                "desired_eni_id",
                "ambiguous_observed_at",
                "settled_at",
                "settled_eni_id",
                "authoritative_read_count",
                "blind_retry_count",
                "completed",
            },
            "ambiguous settlement evidence",
        )
        _string(ambiguous["domain_id"], "ambiguous settlement domain", pattern=_ID_RE)
        _string(
            ambiguous["transaction_id_sha256"],
            "ambiguous transaction ID SHA",
            pattern=_SHA_RE,
        )
        _integer(ambiguous["fence_term"], "ambiguous settlement fence", 1)
        _validate_prefix(ambiguous["destination_prefix"], "ambiguous destination")
        for name in ("desired_eni_id", "settled_eni_id"):
            _string(ambiguous[name], f"ambiguous settlement {name}", pattern=_ENI_RE)
        if parse_timestamp(ambiguous["settled_at"], "ambiguous settled_at") < parse_timestamp(
            ambiguous["ambiguous_observed_at"], "ambiguous observed_at"
        ):
            raise EvidenceError("ambiguous settlement predates the ambiguous call")
        _integer(
            ambiguous["authoritative_read_count"], "ambiguous authoritative reads", 2, 128
        )
        _integer(ambiguous["blind_retry_count"], "ambiguous blind retries", 0, 128)
        _boolean(ambiguous["completed"], "ambiguous settlement completed")

    mutation = _mapping(evidence["mutation_audit"], "evidence mutation audit")
    _exact_keys(
        mutation,
        {
            "runner_identity",
            "session_explicit_deny",
            "route_mutation_calls",
            "advertisement_mutation_calls",
            "denied_attempts",
            "allowed_fault_calls",
            "remote_execution",
            "actor_validations",
        },
        "evidence mutation audit",
    )
    identity = _mapping(mutation["runner_identity"], "runner identity")
    _exact_keys(
        identity,
        {"account_id_sha256", "principal_arn_sha256", "session_name_sha256"},
        "runner identity",
    )
    for name, digest in identity.items():
        _string(digest, f"runner identity {name}", pattern=_SHA_RE)
    _optional_string(mutation["session_explicit_deny"], "session explicit deny")
    _integer(mutation["route_mutation_calls"], "route mutation calls")
    _integer(mutation["advertisement_mutation_calls"], "advertisement mutation calls")
    _string_list(
        mutation["denied_attempts"],
        "denied mutation attempts",
        unique_required=False,
    )
    _string_list(
        mutation["allowed_fault_calls"],
        "allowed fault calls",
        unique_required=False,
    )
    remote = _mapping(mutation["remote_execution"], "remote execution audit")
    _exact_keys(remote, {"workload_calls", "target_calls", "router_calls"}, "remote execution audit")
    for name, count in remote.items():
        _integer(count, f"remote execution {name}")
    actor_validations = mutation["actor_validations"]
    if not isinstance(actor_validations, list) or len(actor_validations) > 2048:
        raise EvidenceError("actor validations must be a bounded list")
    for index, raw_validation in enumerate(actor_validations):
        validation = _mapping(raw_validation, f"actor validation {index}")
        _exact_keys(
            validation,
            {
                "operation",
                "actor_type",
                "actor_id",
                "instance_id",
                "region",
                "identity_sha256",
            },
            f"actor validation {index}",
        )
        if validation["operation"] not in {
            "ssm:SendCommand",
            "ec2:StopInstances",
            "ec2:StartInstances",
        }:
            raise EvidenceError("actor validation operation is unsupported")
        if validation["actor_type"] not in {"controller", "router", "workload"}:
            raise EvidenceError("actor validation type is unsupported")
        _string(validation["actor_id"], "actor validation ID", pattern=_ID_RE)
        _string(
            validation["instance_id"],
            "actor validation instance",
            pattern=_INSTANCE_RE,
        )
        _string(validation["region"], "actor validation region", pattern=_REGION_RE)
        _string(
            validation["identity_sha256"],
            "actor validation identity SHA",
            pattern=_SHA_RE,
        )

    cleanup = _mapping(evidence["cleanup"], "evidence cleanup")
    _exact_keys(
        cleanup,
        {
            "attempted",
            "status",
            "sequence",
            "controller_quiesced",
            "controller_destroyed",
            "material_deleted",
            "appliance_destroyed",
            "tailnet_cleaned",
            "backend_finalized",
            "audits",
            "residual_count",
            "errors",
        },
        "evidence cleanup",
    )
    attempted = _boolean(cleanup["attempted"], "cleanup attempted")
    if cleanup["status"] not in {"complete", "failed", "not-required"}:
        raise EvidenceError("cleanup status is invalid")
    sequence = _string_list(cleanup["sequence"], "cleanup sequence")
    for name in (
        "controller_quiesced",
        "controller_destroyed",
        "material_deleted",
        "appliance_destroyed",
        "tailnet_cleaned",
        "backend_finalized",
    ):
        _boolean(cleanup[name], f"cleanup {name}")
    if not isinstance(cleanup["audits"], list):
        raise EvidenceError("cleanup audits must be a list")
    audit_total = 0
    for index, raw_audit in enumerate(cleanup["audits"]):
        audit = _mapping(raw_audit, f"cleanup audit {index}")
        _exact_keys(audit, {"hook", "residual_count"}, f"cleanup audit {index}")
        _string(audit["hook"], "cleanup audit hook", pattern=_ID_RE)
        audit_total += _integer(audit["residual_count"], "cleanup audit residual count")
    residual_count = _integer(cleanup["residual_count"], "cleanup residual count")
    if residual_count != audit_total:
        raise EvidenceError("cleanup residual total differs from audit hooks")
    audit_hooks = [audit["hook"] for audit in cleanup["audits"]]
    if cleanup["status"] == "complete" and audit_hooks != list(
        RESIDUAL_AUDIT_HOOKS
    ):
        raise EvidenceError("complete cleanup requires every exact residual audit hook")
    if not isinstance(cleanup["errors"], list) or not all(
        isinstance(item, str) and item for item in cleanup["errors"]
    ):
        raise EvidenceError("cleanup errors must be a bounded string list")
    if cleanup["status"] == "complete":
        if (
            attempted is not True
            or sequence != list(COMPLETE_CLEANUP_SEQUENCE)
            or not all(
                cleanup[name]
                for name in (
                    "controller_quiesced",
                    "controller_destroyed",
                    "material_deleted",
                    "appliance_destroyed",
                    "tailnet_cleaned",
                    "backend_finalized",
                )
            )
            or residual_count != 0
            or any(audit["residual_count"] != 0 for audit in cleanup["audits"])
            or cleanup["errors"]
        ):
            raise EvidenceError(
                "complete cleanup must prove the exact ordered zero-residual lifecycle"
            )
    elif cleanup["status"] == "not-required":
        expected_not_required = {
            "attempted": False,
            "status": "not-required",
            "sequence": [],
            "controller_quiesced": False,
            "controller_destroyed": False,
            "material_deleted": False,
            "appliance_destroyed": False,
            "tailnet_cleaned": False,
            "backend_finalized": False,
            "audits": [],
            "residual_count": 0,
            "errors": [],
        }
        if evidence["status"] != "failed" or cleanup != expected_not_required:
            raise EvidenceError(
                "not-required cleanup is valid only as exact empty failed evidence"
            )
    elif attempted is not True:
        raise EvidenceError("armed cleanup evidence must record attempted=true")
    if evidence["failure"] is not None:
        failure = _mapping(evidence["failure"], "evidence failure")
        _exact_keys(failure, {"stage", "category", "message"}, "evidence failure")
        for name in failure:
            _string(failure[name], f"failure {name}", maximum=512)
    return evidence


def _stage_observations(evidence: Mapping[str, Any], stage: str) -> list[dict[str, Any]]:
    return [
        validate_observation(value, expected_stage=stage)
        for value in cast(Sequence[Any], evidence["observations"])
        if isinstance(value, Mapping) and value.get("stage") == stage
    ]


def verify_evidence(value: Any) -> dict[str, Any]:
    evidence = validate_evidence(value)
    if evidence["status"] != "passed" or evidence["failure"] is not None:
        raise EvidenceError("passing verification requires terminal passed evidence")
    topology = _mapping(evidence["topology"], "passing topology")
    controller_ids = set(topology["controller_ids"])
    actor_summary = validate_actor_summary(evidence["actors"])
    actor_instances = actor_summary["instances"]
    actors_by_key = {
        (actor["actor_type"], actor["actor_id"]): actor
        for actor in actor_instances
    }
    controller_actors = {
        actor_id: actors_by_key.get(("controller", actor_id))
        for actor_id in controller_ids
    }
    authority_router_values: dict[str, Mapping[str, Any]] = {}
    authority_sites: dict[str, tuple[str, str]] = {}
    for domain in topology["gwlbe_authority"]:
        authority_sites[str(domain["site_id"])] = (
            str(domain["region"]),
            str(domain["vpc_id"]),
        )
        for router in domain["eligible_routers"]:
            prior = authority_router_values.get(str(router["router_id"]))
            if prior is not None and prior != router:
                raise EvidenceError("router actor authority differs across route domains")
            authority_router_values[str(router["router_id"])] = router
    expected_actor_keys = {
        *(("controller", controller_id) for controller_id in controller_ids),
        *(("router", router_id) for router_id in authority_router_values),
        *(
            ("workload", f"{site_id}-{role}")
            for site_id in authority_sites
            for role in ("initiator", "responder")
        ),
    }
    if set(actors_by_key) != expected_actor_keys or any(
        actor is None for actor in controller_actors.values()
    ):
        raise EvidenceError(
            "passing evidence does not bind every controller, router, and workload actor"
        )
    for router_id, authority_router in authority_router_values.items():
        actor = actors_by_key[("router", router_id)]
        matching_domains = [
            domain
            for domain in topology["gwlbe_authority"]
            if any(
                router["router_id"] == router_id
                for router in domain["eligible_routers"]
            )
        ]
        if (
            actor["instance_id"] != authority_router["instance_id"]
            or any(
                actor["region"] != domain["region"]
                or actor["vpc_id"] != domain["vpc_id"]
                for domain in matching_domains
            )
        ):
            raise EvidenceError("router actor differs from exact topology authority")
    for site_id, (region, vpc_id) in authority_sites.items():
        site_prefixes = [
            ipaddress.ip_network(domain["source_prefix"])
            for domain in topology["gwlbe_authority"]
            if domain["site_id"] == site_id
        ]
        for role in ("initiator", "responder"):
            actor = actors_by_key[("workload", f"{site_id}-{role}")]
            if (
                actor["region"] != region
                or actor["vpc_id"] != vpc_id
                or not any(
                    ipaddress.ip_address(actor["private_ip"]) in prefix
                    for prefix in site_prefixes
                )
            ):
                raise EvidenceError("workload actor differs from exact site authority")
    artifacts = _mapping(evidence["artifacts"], "passing artifacts")
    _exact_keys(
        artifacts,
        {"manifest_sha256", "revision", "version", "architecture", "objects"},
        "passing artifacts",
    )
    _string(artifacts["manifest_sha256"], "artifact manifest SHA", pattern=_SHA_RE)
    _string(artifacts["revision"], "artifact revision", pattern=re.compile(r"[0-9a-f]{40}"))
    _string(artifacts["version"], "artifact version")
    if artifacts["architecture"] not in {"amd64", "arm64"}:
        raise EvidenceError("artifact architecture is invalid")
    objects = artifacts["objects"]
    if not isinstance(objects, list) or len(objects) != 2:
        raise EvidenceError("passing evidence requires two immutable controller objects")
    components: set[str] = set()
    object_keys: set[str] = set()
    version_ids: set[str] = set()
    for index, raw_object in enumerate(objects):
        artifact = _mapping(raw_object, f"artifact object {index}")
        _exact_keys(
            artifact,
            {"component", "key", "version_id", "sha256"},
            f"artifact object {index}",
        )
        components.add(_string(artifact["component"], "artifact component"))
        key = _string(artifact["key"], "artifact key")
        if not key.startswith(
            f"runs/{evidence['run_id']}/controller/{artifacts['revision']}/"
        ):
            raise EvidenceError("immutable controller artifact key is not run-scoped")
        object_keys.add(key)
        version_ids.add(_string(artifact["version_id"], "artifact version ID"))
        _string(artifact["sha256"], "artifact SHA", pattern=_SHA_RE)
    if (
        components != {"envelope-controller", "envelope-controller-topology"}
        or len(object_keys) != 2
        or len(version_ids) != 2
    ):
        raise EvidenceError("immutable artifacts do not contain both controller components")

    rollout = _mapping(evidence["rollout"], "passing rollout")
    _exact_keys(
        rollout,
        {"order", "read_only_validated_at", "active_promoted_at", "exact_route_table_arns"},
        "passing rollout",
    )
    order = _string_list(rollout["order"], "rollout order")
    if order != ["read-only-deployed", "read-only-cold-validated", "active-promoted"]:
        raise EvidenceError("controller was not validated read-only before active promotion")
    if parse_timestamp(rollout["active_promoted_at"], "active promoted_at") <= parse_timestamp(
        rollout["read_only_validated_at"], "read-only validated_at"
    ):
        raise EvidenceError("active promotion did not follow read-only validation")
    route_arns = _string_list(
        rollout["exact_route_table_arns"], "exact route table ARNs", minimum=1, sorted_required=True
    )
    if len(route_arns) != len(topology["domain_ids"]):
        raise EvidenceError("active IAM route-table scope does not cover each exact domain once")
    expected_route_table_ids = {
        domain["route_table_id"] for domain in topology["gwlbe_authority"]
    }
    if {
        route_arn.rsplit("/", 1)[-1] for route_arn in route_arns
    } != expected_route_table_ids:
        raise EvidenceError("active IAM route-table scope differs from topology authority")

    expected_secret_purposes = {
        "controller-admin-readonly",
        "controller-tsnet",
        "router-east",
        "router-west",
    }
    if {
        reference["purpose"] for reference in evidence["secret_references"]["parameters"]
    } != expected_secret_purposes:
        raise EvidenceError("passing evidence omits an exact protected secret reference")

    domain_ids = set(topology["domain_ids"])
    authority_by_domain = {
        domain["domain_id"]: domain for domain in topology["gwlbe_authority"]
    }
    policy = topology["policy"]
    required_quorum = policy["observation_quorum"]

    def verify_observation_authority(item: Mapping[str, Any]) -> None:
        domain_id = str(item["domain_id"])
        authority = authority_by_domain[domain_id]
        if item["preferred_owner"] != authority["preferred_owner"]:
            raise EvidenceError("observation preferred owner differs from topology authority")
        route_table = item["aws_route_table"]
        expected_table = {
            "route_table_id": authority["route_table_id"],
            "vpc_id": authority["vpc_id"],
            "gwlbe_subnet_id": authority["gwlbe_subnet_id"],
            "route_table_association_id": authority["route_table_association_id"],
        }
        if (
            any(route_table[name] != expected for name, expected in expected_table.items())
            or route_table["explicit_association_count"] != 1
            or route_table["association_state"] != "associated"
            or route_table["stable_read_count"] < 2
        ):
            raise EvidenceError("route-table observation differs from exact topology authority")
        expected_prefixes = set(authority["remote_prefixes"])
        routes = item["aws_routes"]
        if {route["destination_prefix"] for route in routes} != expected_prefixes or len(
            routes
        ) != len(expected_prefixes):
            raise EvidenceError("AWS route observation does not cover every exact remote prefix")
        eligible = {
            router["router_id"]: router for router in authority["eligible_routers"]
        }
        for route in routes:
            router = eligible.get(route["target_router_id"])
            if router is None or route["target_eni_id"] != router["eni_id"]:
                raise EvidenceError("AWS route target is not the selected router's exact eligible ENI")

        endpoints = item["controller_endpoints"]
        for endpoint in endpoints:
            actor = controller_actors[endpoint["controller_id"]]
            assert actor is not None
            if (
                endpoint["instance_id"] != actor["instance_id"]
                or endpoint["private_ip"] != actor["private_ip"]
            ):
                raise EvidenceError(
                    "controller endpoint is not bound to its exact runtime actor"
                )
        if item["dynamodb"]["present"]:
            live = [
                endpoint
                for endpoint in endpoints
                if endpoint["health_status"] == 200
                and endpoint["ready_status"] == 200
                and endpoint["mode"] == "active"
            ]
            leaders = [endpoint for endpoint in live if endpoint["role"] == "leader"]
            if (
                len(live) < required_quorum
                or len(leaders) != 1
                or leaders[0]["controller_id"]
                != item["dynamodb"]["lease_holder"]
                or leaders[0]["fence_term"] != item["dynamodb"]["fence_term"]
                or leaders[0]["phase"] != item["dynamodb"]["phase"]
            ):
                raise EvidenceError(
                    "controller endpoint liveness does not bind the durable leader and fence"
                )

        tailnet = item["tailnet"]
        contributors = tailnet["contributors"]
        contributor_order = [contributor["controller_id"] for contributor in contributors]
        if (
            contributor_order != sorted(contributor_order)
            or not set(contributor_order).issubset(controller_ids)
        ):
            raise EvidenceError("observer contributor is not a configured controller")
        observation_at = parse_timestamp(item["captured_at"], "observation captured_at")
        freshness_ms = policy["observation_freshness_milliseconds"]
        fresh = []
        for contributor in contributors:
            captured_at = parse_timestamp(
                contributor["captured_at"], "contributor captured_at"
            )
            expires_at = parse_timestamp(contributor["expires_at"], "contributor expires_at")
            derived_fresh = (
                captured_at <= observation_at + dt.timedelta(seconds=5)
                and int((observation_at - captured_at).total_seconds() * 1000)
                <= freshness_ms
                and expires_at > observation_at
            )
            if contributor["fresh"] is not derived_fresh:
                raise EvidenceError("observer contributor freshness flag differs from timestamps")
            if derived_fresh and contributor["backend_healthy"]:
                fresh.append(contributor)
        if tailnet["agreement"]:
            owner = eligible.get(tailnet["owner_router_id"])
            if owner is None or tailnet["owner_node_sha256"] != owner["stable_node_sha256"]:
                raise EvidenceError("observer owner hash is not bound to an eligible router")
            qualifying = [
                contributor
                for contributor in fresh
                if contributor["sole_primary"]
                and contributor["owner_healthy"]
                and contributor["owner_node_sha256"] == tailnet["owner_node_sha256"]
            ]
            if len(qualifying) < required_quorum or tailnet["observer_quorum"] != len(
                qualifying
            ):
                raise EvidenceError("observation does not prove the configured distinct quorum")
        else:
            reports = {contributor["owner_node_sha256"] for contributor in fresh}
            no_sole_owner = any(not contributor["sole_primary"] for contributor in fresh)
            if (
                tailnet["owner_router_id"] is not None
                or tailnet["owner_node_sha256"] is not None
                or tailnet["observer_quorum"] != 0
                or len(fresh) < required_quorum
                or len(reports) < 2
                and not no_sole_owner
            ):
                raise EvidenceError("observer disagreement evidence is not distinct and fail-closed")

        route_owners = {route["target_router_id"] for route in routes}
        if item["route_agreement"]:
            expected_owner = (
                item["dynamodb"]["stable_owner"]
                if item["dynamodb"]["present"]
                else tailnet["owner_router_id"]
            )
            if (
                not tailnet["agreement"]
                or len(route_owners) != 1
                or next(iter(route_owners)) != expected_owner
                or tailnet["owner_router_id"] != expected_owner
            ):
                raise EvidenceError("route agreement is inconsistent with durable and observer owners")

    for stage in STAGES:
        observations = _stage_observations(evidence, stage)
        if (
            len(observations) != len(domain_ids)
            or {item["domain_id"] for item in observations} != domain_ids
            or any(
                {endpoint["controller_id"] for endpoint in item["controller_endpoints"]}
                != controller_ids
                or item["dynamodb"]["lease_holder"] is not None
                and item["dynamodb"]["lease_holder"] not in controller_ids
                for item in observations
            )
        ):
            raise EvidenceError(f"passing evidence does not cover every domain at {stage}")
        for observation in observations:
            verify_observation_authority(observation)
    cold = _stage_observations(evidence, "read-only-cold")
    if any(
        item["dynamodb"]["present"] is not False
        or item["route_agreement"] is not True
        or any(
            endpoint["mode"] != "read-only"
            or endpoint["role"] != "read-only"
            or endpoint["health_status"] != 200
            or endpoint["ready_status"] != 503
            or endpoint["ready_reason"] != "domain-not-initialized"
            for endpoint in item["controller_endpoints"]
        )
        for item in cold
    ):
        raise EvidenceError("read-only rollout did not prove the expected empty cold state")

    faults = _mapping(evidence["faults"], "passing faults")
    _exact_keys(faults, {"router", "leader"}, "passing faults")
    router_fault = _mapping(faults["router"], "router fault")
    _exact_keys(
        router_fault,
        {"domain_id", "router_id", "alternate_router_id", "instance_id", "injected_at", "restored_at", "method"},
        "router fault",
    )
    if router_fault["method"] != "ec2-stop-instance":
        raise EvidenceError("router failure was not an external EC2 stop fault")
    for name in ("domain_id", "router_id", "alternate_router_id"):
        _string(router_fault[name], f"router fault {name}", pattern=_ID_RE)
    _string(router_fault["instance_id"], "router fault instance", pattern=_INSTANCE_RE)
    injected_at = parse_timestamp(router_fault["injected_at"], "router fault injected_at")
    restored_at = parse_timestamp(router_fault["restored_at"], "router fault restored_at")
    if restored_at <= injected_at:
        raise EvidenceError("router restoration did not follow failure injection")
    selected_domain = router_fault["domain_id"]
    authority = authority_by_domain.get(selected_domain)
    if authority is None:
        raise EvidenceError("router fault domain is outside topology authority")
    eligible = {router["router_id"]: router for router in authority["eligible_routers"]}
    if (
        router_fault["router_id"] not in eligible
        or router_fault["alternate_router_id"] not in eligible
        or router_fault["router_id"] == router_fault["alternate_router_id"]
        or router_fault["instance_id"] != eligible[router_fault["router_id"]]["instance_id"]
    ):
        raise EvidenceError("router fault identities are not distinct eligible routers")

    def selected_at(stage: str) -> dict[str, Any]:
        selected = next(
            (
                item
                for item in _stage_observations(evidence, stage)
                if item["domain_id"] == selected_domain
            ),
            None,
        )
        if selected is None:
            raise EvidenceError(f"selected route domain is absent at {stage}")
        return selected

    baseline = selected_at("active-baseline")
    renewed = selected_at("lease-renewal")
    disagreement = selected_at("observer-disagreement")
    progress = selected_at("route-progress")
    failover = next(
        (item for item in _stage_observations(evidence, "router-failover") if item["domain_id"] == selected_domain),
        None,
    )
    durable = next(
        (item for item in _stage_observations(evidence, "durable-alternate") if item["domain_id"] == selected_domain),
        None,
    )
    gate = next(
        (item for item in _stage_observations(evidence, "failback-gate") if item["domain_id"] == selected_domain),
        None,
    )
    failed_back = next(
        (item for item in _stage_observations(evidence, "failback-stable") if item["domain_id"] == selected_domain),
        None,
    )
    if any(item is None for item in (failover, durable, gate, failed_back)):
        raise EvidenceError("selected route domain has incomplete failover/failback observations")
    assert failover and durable and gate and failed_back
    alternate = router_fault["alternate_router_id"]
    preferred = failover["preferred_owner"]
    renewal_interval_ms = policy["lease_renew_interval_milliseconds"]
    if (
        baseline["dynamodb"]["lease_holder"] is None
        or renewed["dynamodb"]["lease_holder"] != baseline["dynamodb"]["lease_holder"]
        or renewed["dynamodb"]["fence_term"] != baseline["dynamodb"]["fence_term"]
        or renewed["dynamodb"]["lease_record_version"]
        <= baseline["dynamodb"]["lease_record_version"]
        or parse_timestamp(renewed["dynamodb"]["lease_renewed_at"], "renewed lease time")
        <= parse_timestamp(baseline["dynamodb"]["lease_renewed_at"], "baseline lease time")
        or parse_timestamp(renewed["dynamodb"]["lease_expires_at"], "renewed lease expiry")
        <= parse_timestamp(baseline["dynamodb"]["lease_expires_at"], "baseline lease expiry")
        or int(
            (
                parse_timestamp(renewed["captured_at"], "renewal captured_at")
                - parse_timestamp(baseline["captured_at"], "baseline captured_at")
            ).total_seconds()
            * 1000
        )
        < renewal_interval_ms
    ):
        raise EvidenceError("evidence does not prove an actual same-fence lease renewal")
    if (
        disagreement["dynamodb"]["phase"] != "degraded"
        or disagreement["dynamodb"]["stable_owner"] != preferred
        or disagreement["dynamodb"]["error_code"] != "observation-quorum"
        or disagreement["tailnet"]["agreement"] is not False
        or disagreement["route_agreement"] is not False
        or disagreement["aws_route_table"]["snapshot_sha256"]
        != baseline["aws_route_table"]["snapshot_sha256"]
        or parse_timestamp(disagreement["captured_at"], "disagreement captured_at")
        < injected_at
    ):
        raise EvidenceError("observer disagreement did not retain the prior route in degraded state")
    transaction = progress["dynamodb"]["transaction"]
    if (
        progress["dynamodb"]["phase"]
        not in {"route-intent-persisted", "routes-converging"}
        or transaction is None
        or transaction["fence_term"] != progress["dynamodb"]["fence_term"]
        or transaction["desired_owner"] != alternate
        or transaction["desired_eni_id"] != eligible[alternate]["eni_id"]
        or transaction["before_sha256"] != baseline["aws_route_table"]["snapshot_sha256"]
        or [entry["destination_prefix"] for entry in transaction["progress"]]
        != authority["remote_prefixes"]
        or all(entry["completed"] for entry in transaction["progress"])
        or parse_timestamp(progress["captured_at"], "route progress captured_at") < injected_at
    ):
        raise EvidenceError("leader failure checkpoint is not a journaled in-progress route transaction")
    if (
        failover["tailnet"]["owner_router_id"] != alternate
        or failover["tailnet"]["failed_router_online"] is not False
        or failover["dynamodb"]["stable_owner"] != alternate
        or not failover["route_agreement"]
        or any(route["target_router_id"] != alternate for route in failover["aws_routes"])
        or failover["aws_route_table"]["stable_read_count"] < 2
        or durable["dynamodb"]["stable_owner"] != alternate
        or not durable["route_agreement"]
        or any(route["target_router_id"] != alternate for route in durable["aws_routes"])
    ):
        raise EvidenceError("router failure did not prove native owner and durable alternate route convergence")
    if (
        gate["tailnet"]["owner_router_id"] != preferred
        or gate["dynamodb"]["stable_owner"] != alternate
        or gate["dynamodb"]["phase"] != "owner-observed"
        or gate["dynamodb"]["owner_observed_at"] is None
        or gate["dynamodb"]["cooldown_until"] is None
        or any(route["target_router_id"] != alternate for route in gate["aws_routes"])
        or failed_back["dynamodb"]["stable_owner"] != preferred
        or failed_back["dynamodb"]["phase"] != "stable"
        or not failed_back["route_agreement"]
        or any(route["target_router_id"] != preferred for route in failed_back["aws_routes"])
    ):
        raise EvidenceError("evidence does not prove stability-gated failback")
    failback_at = parse_timestamp(failed_back["captured_at"], "failback captured_at")
    owner_observed_at = parse_timestamp(
        gate["dynamodb"]["owner_observed_at"], "failback owner_observed_at"
    )
    cooldown_until = parse_timestamp(
        gate["dynamodb"]["cooldown_until"], "failback cooldown_until"
    )
    failback_stability_ms = policy["failback_stability_milliseconds"]
    preferred_hash = eligible[preferred]["stable_node_sha256"]
    stable_contributors = [
        contributor
        for contributor in failed_back["tailnet"]["contributors"]
        if contributor["fresh"]
        and contributor["backend_healthy"]
        and contributor["sole_primary"]
        and contributor["owner_healthy"]
        and contributor["owner_node_sha256"] == preferred_hash
        and contributor["owner_since"] is not None
        and int(
            (
                failback_at
                - parse_timestamp(contributor["owner_since"], "preferred owner_since")
            ).total_seconds()
            * 1000
        )
        >= failback_stability_ms
    ]
    if (
        int((failback_at - owner_observed_at).total_seconds() * 1000)
        < failback_stability_ms
        or failback_at < cooldown_until
        or len(stable_contributors) < required_quorum
    ):
        raise EvidenceError("failback did not satisfy cooldown and continuous owner stability")

    leader_fault = _mapping(faults["leader"], "leader fault")
    _exact_keys(
        leader_fault,
        {
            "domain_id",
            "previous_controller_id",
            "new_controller_id",
            "instance_id",
            "previous_fence",
            "new_fence",
            "injected_at",
            "method",
            "checkpoint_phase",
            "transaction_id_sha256",
            "journaled_progress_count",
        },
        "leader fault",
    )
    previous_controller_actor = controller_actors.get(
        str(leader_fault.get("previous_controller_id"))
    )
    if (
        leader_fault["method"] != "ec2-stop-instance"
        or leader_fault["domain_id"] != selected_domain
        or leader_fault["previous_controller_id"] not in controller_ids
        or leader_fault["new_controller_id"] not in controller_ids
        or leader_fault["new_controller_id"] == leader_fault["previous_controller_id"]
        or _integer(leader_fault["new_fence"], "new leader fence", 1)
        <= _integer(leader_fault["previous_fence"], "previous leader fence", 1)
        or leader_fault["checkpoint_phase"]
        not in {"route-intent-persisted", "routes-converging"}
        or leader_fault["previous_controller_id"]
        != progress["dynamodb"]["lease_holder"]
        or leader_fault["previous_fence"] != progress["dynamodb"]["fence_term"]
        or leader_fault["previous_fence"] != transaction["fence_term"]
        or leader_fault["transaction_id_sha256"] != transaction["transaction_id_sha256"]
        or previous_controller_actor is None
        or leader_fault["instance_id"]
        != previous_controller_actor["instance_id"]
        or _integer(
            leader_fault["journaled_progress_count"], "journaled route progress count", 0
        )
        != sum(entry["attempted"] or entry["completed"] for entry in transaction["progress"])
    ):
        raise EvidenceError("leader failure did not prove a distinct higher-fence handoff")
    _string(leader_fault["instance_id"], "leader fault instance", pattern=_INSTANCE_RE)
    leader_injected_at = parse_timestamp(leader_fault["injected_at"], "leader fault injected_at")
    handoff = selected_at("leader-handoff")
    new_controller_actor = controller_actors[leader_fault["new_controller_id"]]
    assert new_controller_actor is not None
    handoff_leader = next(
        (
            endpoint
            for endpoint in handoff["controller_endpoints"]
            if endpoint["controller_id"] == leader_fault["new_controller_id"]
        ),
        None,
    )
    if (
        leader_injected_at < parse_timestamp(progress["captured_at"], "progress captured_at")
        or parse_timestamp(handoff["captured_at"], "handoff captured_at") < leader_injected_at
        or handoff["dynamodb"]["lease_holder"] != leader_fault["new_controller_id"]
        or handoff["dynamodb"]["fence_term"] != leader_fault["new_fence"]
        or handoff_leader is None
        or handoff_leader["instance_id"] != new_controller_actor["instance_id"]
        or handoff_leader["role"] != "leader"
        or handoff_leader["health_status"] != 200
        or handoff_leader["ready_status"] != 200
        or handoff_leader["fence_term"] != leader_fault["new_fence"]
        or handoff["dynamodb"]["stable_owner"] != alternate
        or not handoff["route_agreement"]
    ):
        raise EvidenceError("successor did not settle the journaled transaction after leader loss")

    control_plane = evidence["control_plane"]
    stale = _mapping(control_plane["stale_fence_rejection"], "passing stale-fence evidence")
    if (
        stale["domain_id"] != selected_domain
        or stale["stale_controller_id"] != leader_fault["previous_controller_id"]
        or stale["stale_fence"] != leader_fault["previous_fence"]
        or stale["current_fence"] != leader_fault["new_fence"]
        or stale["current_fence"] <= stale["stale_fence"]
        or stale["stale_write_rejected"] is not True
        or stale["stale_route_calls"] != 0
        or stale["route_snapshot_before_sha256"]
        != stale["route_snapshot_after_sha256"]
        or stale["route_snapshot_before_sha256"]
        != handoff["aws_route_table"]["snapshot_sha256"]
        or stale["state_revision_before"] != handoff["dynamodb"]["revision"]
        or stale["state_revision_after"] < stale["state_revision_before"]
        or parse_timestamp(stale["observed_at"], "stale rejection observed_at")
        < parse_timestamp(handoff["captured_at"], "handoff captured_at")
    ):
        raise EvidenceError("evidence does not prove stale-fence rejection without a route call")
    ambiguous = _mapping(control_plane["ambiguous_settlement"], "passing ambiguous evidence")
    ambiguous_observed_at = parse_timestamp(
        ambiguous["ambiguous_observed_at"], "ambiguous observed_at"
    )
    ambiguous_settled_at = parse_timestamp(
        ambiguous["settled_at"], "ambiguous settled_at"
    )
    if (
        ambiguous["domain_id"] != selected_domain
        or ambiguous["transaction_id_sha256"]
        != transaction["transaction_id_sha256"]
        or ambiguous["fence_term"] != leader_fault["new_fence"]
        or ambiguous["fence_term"] != handoff["dynamodb"]["fence_term"]
        or ambiguous["destination_prefix"] not in authority["remote_prefixes"]
        or ambiguous["desired_eni_id"] != transaction["desired_eni_id"]
        or ambiguous["desired_eni_id"] != ambiguous["settled_eni_id"]
        or ambiguous["desired_eni_id"] not in {
            router["eni_id"] for router in authority["eligible_routers"]
        }
        or next(
            route
            for route in handoff["aws_routes"]
            if route["destination_prefix"] == ambiguous["destination_prefix"]
        )["target_eni_id"]
        != ambiguous["settled_eni_id"]
        or ambiguous["blind_retry_count"] != 0
        or ambiguous["completed"] is not True
        or ambiguous_observed_at
        < parse_timestamp(handoff["captured_at"], "handoff captured_at")
        or ambiguous_settled_at < ambiguous_observed_at
        or ambiguous_settled_at
        > parse_timestamp(durable["captured_at"], "durable alternate captured_at")
    ):
        raise EvidenceError("evidence does not prove authoritative ambiguous-call settlement")

    flow_index = {
        (flow["stage"], flow["protocol"]): validate_flow(flow)
        for flow in evidence["fresh_flows"]
    }
    expected_flows = {
        (stage, protocol)
        for stage in ("router-failover", "failback-stable")
        for protocol in ("tcp", "udp")
    }
    if (
        len(evidence["fresh_flows"]) != len(expected_flows)
        or set(flow_index) != expected_flows
        or any(
            flow["success"] is not True
            or flow["responder_acknowledged"] is not True
            or flow["messages_sent"] != 1
            or flow["messages_received"] != 1
            or flow["loss_basis_points"] != 0
            for flow in flow_index.values()
        )
    ):
        raise EvidenceError("passing evidence requires fresh TCP and UDP retry after failover and failback")
    convergence_times = {
        "router-failover": parse_timestamp(failover["captured_at"], "failover captured_at"),
        "failback-stable": parse_timestamp(failed_back["captured_at"], "failback captured_at"),
    }
    if any(
        parse_timestamp(flow["started_at"], "fresh flow started_at") < convergence_times[stage]
        or parse_timestamp(flow["convergence_at"], "fresh flow convergence_at")
        != convergence_times[stage]
        or parse_timestamp(flow["event_at"], "fresh flow event_at")
        != (injected_at if stage == "router-failover" else restored_at)
        for (stage, _protocol), flow in flow_index.items()
    ):
        raise EvidenceError("fresh retry evidence is not bound to its fault and route convergence")
    established = [validate_established_flow(flow) for flow in evidence["established_flows"]]
    if (
        len(established) != 2
        or {flow["protocol"] for flow in established} != {"tcp", "udp"}
        or any(
            flow["fault_injected_at"] != router_fault["injected_at"]
            or flow["convergence_at"] != failover["captured_at"]
            or flow["one_socket"] is not True
            or flow["agent_output_verified"] is not True
            for flow in established
        )
    ):
        raise EvidenceError("established TCP and UDP outcomes were not bounded and classified")

    all_flows = [*flow_index.values(), *established]
    for flow in all_flows:
        source = actors_by_key.get(("workload", flow["source_workload"]))
        destination = actors_by_key.get(
            ("workload", flow["destination_workload"])
        )
        if (
            source is None
            or destination is None
            or source["instance_id"] != flow["source_instance_id"]
            or destination["instance_id"] != flow["destination_instance_id"]
            or source["instance_id"] == destination["instance_id"]
        ):
            raise EvidenceError(
                "flow evidence is not bound to exact workload instance actors"
            )

    mutation = evidence["mutation_audit"]
    actor_validations = mutation["actor_validations"]
    for validation in actor_validations:
        actor = actors_by_key.get(
            (validation["actor_type"], validation["actor_id"])
        )
        if (
            actor is None
            or validation["instance_id"] != actor["instance_id"]
            or validation["region"] != actor["region"]
            or validation["identity_sha256"] != canonical_sha256(actor)
        ):
            raise EvidenceError(
                "runtime actor validation is not bound to immutable actor evidence"
            )
    ssm_validations = [
        validation
        for validation in actor_validations
        if validation["operation"] == "ssm:SendCommand"
    ]
    fault_validations = [
        (validation["operation"], validation["instance_id"])
        for validation in actor_validations
        if validation["operation"]
        in {"ec2:StopInstances", "ec2:StartInstances"}
    ]
    expected_workload_calls = 4 + sum(
        flow["attempts"] for flow in flow_index.values()
    )
    if len({flow["source_instance_id"] for flow in established}) != 1:
        raise EvidenceError("established flows do not share one exact source actor")
    expected_ssm_instances = sorted(
        [
            instance_id
            for flow in flow_index.values()
            for instance_id in [flow["source_instance_id"]] * flow["attempts"]
        ]
        + [established[0]["source_instance_id"]] * 4
    )
    expected_fault_validations = sorted(
        [
            ("ec2:StopInstances", router_fault["instance_id"]),
            ("ec2:StopInstances", leader_fault["instance_id"]),
            ("ec2:StartInstances", leader_fault["instance_id"]),
            ("ec2:StartInstances", router_fault["instance_id"]),
        ]
    )
    if (
        mutation["session_explicit_deny"] != SESSION_ROUTE_DENY_EVIDENCE
        or mutation["route_mutation_calls"] != 0
        or mutation["advertisement_mutation_calls"] != 0
        or mutation["denied_attempts"]
        or mutation["remote_execution"]["target_calls"] != 0
        or mutation["remote_execution"]["router_calls"] != 0
        or mutation["remote_execution"]["workload_calls"]
        != expected_workload_calls
        or len(ssm_validations) != expected_workload_calls
        or any(
            validation["actor_type"] != "workload"
            for validation in ssm_validations
        )
        or sorted(
            validation["instance_id"] for validation in ssm_validations
        )
        != expected_ssm_instances
        or sorted(fault_validations) != expected_fault_validations
        or len(actor_validations)
        != expected_workload_calls + len(expected_fault_validations)
        or sorted(mutation["allowed_fault_calls"])
        != sorted(
            [
                "ec2:StartInstances",
                "ec2:StartInstances",
                "ec2:StopInstances",
                "ec2:StopInstances",
            ]
        )
    ):
        raise EvidenceError("runner mutation audit does not prove the protected observation boundary")
    cleanup = evidence["cleanup"]
    if (
        cleanup["attempted"] is not True
        or cleanup["status"] != "complete"
        or cleanup["sequence"] != list(COMPLETE_CLEANUP_SEQUENCE)
        or [audit["hook"] for audit in cleanup["audits"]] != list(RESIDUAL_AUDIT_HOOKS)
        or not all(
            cleanup[name]
            for name in (
                "controller_quiesced",
                "controller_destroyed",
                "material_deleted",
                "appliance_destroyed",
                "tailnet_cleaned",
                "backend_finalized",
            )
        )
        or cleanup["residual_count"] != 0
        or cleanup["errors"]
    ):
        raise EvidenceError("passing evidence requires ordered complete zero-residual cleanup")
    return evidence


def scan_evidence(value: Any, secrets: Sequence[str] = ()) -> list[str]:
    findings: set[str] = set()
    protected_markers = {
        marker
        for secret in secrets
        if secret
        for marker in (
            secret,
            secret[:32] if len(secret) >= 32 else secret,
            secret[-32:] if len(secret) >= 32 else secret,
        )
    }

    def visit(candidate: Any, path: str) -> None:
        if isinstance(candidate, Mapping):
            for key, child in candidate.items():
                if not isinstance(key, str):
                    findings.add(f"{path}: non-string object key")
                    continue
                lowered = key.lower()
                if lowered in {"secret_value", "auth_key", "api_key", "access_key", "session_token", "password"}:
                    findings.add(f"{path}.{key}: prohibited credential field")
                visit(child, f"{path}.{key}")
        elif isinstance(candidate, list):
            for index, child in enumerate(candidate):
                visit(child, f"{path}[{index}]")
        elif isinstance(candidate, str):
            for marker in protected_markers:
                if marker in candidate:
                    findings.add(f"{path}: protected secret material")
            if any(pattern.search(candidate) for pattern in _SECRET_PATTERNS):
                findings.add(f"{path}: credential-like material")
            if "nodekey:" in candidate.lower() or "stable_node_id" in path.lower():
                findings.add(f"{path}: raw cryptographic node identity")

    visit(value, "$")
    return sorted(findings)


def write_private_json(path: pathlib.Path, value: Mapping[str, Any]) -> None:
    path = pathlib.Path(os.path.abspath(path.expanduser()))
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.exists():
        raise ContractError("evidence path must be a new regular file")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(
                json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
            )
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as error:
            raise ContractError("evidence path already exists") from error
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


@dataclasses.dataclass(frozen=True)
class RunResult:
    exit_code: int
    evidence: dict[str, Any]


class ProductionControllerRunner:
    def __init__(
        self,
        config: ProductionRunConfig,
        adapter: ProductionAdapter,
        evidence_path: pathlib.Path,
        *,
        now: Callable[[], str] = utc_now,
        begin_cleanup: Callable[[], None] | None = None,
        finish_cleanup: Callable[[], Mapping[str, bool]] | None = None,
    ):
        self.config = config
        self.adapter = adapter
        self.evidence_path = evidence_path.expanduser().resolve()
        self.now = now
        self.begin_cleanup = begin_cleanup or (lambda: None)
        self.finish_cleanup = finish_cleanup or (
            lambda: {
                "termination_requested": False,
                "acceptance_timed_out": False,
                "cleanup_timed_out": False,
            }
        )
        self.protected_secrets = protected_environment_secrets(config)
        self.runner_identity: Mapping[str, str] = {
            "account_id": "000000000000",
            "principal_arn": "arn:aws:iam::000000000000:role/uninitialized",
            "session_name": "uninitialized",
        }

    def _initial_evidence(self) -> dict[str, Any]:
        return {
            "schema": EVIDENCE_SCHEMA,
            "kind": EVIDENCE_KIND,
            "run_id": self.config.run_id,
            "status": "failed",
            "started_at": self.now(),
            "completed_at": self.now(),
            "configuration_sha256": self.config.configuration_sha256,
            "state": {
                "appliance_key_sha256": hash_identity(self.config.appliance_state_key),
                "controller_key_sha256": hash_identity(self.config.controller.state_key),
                "distinct": self.config.appliance_state_key != self.config.controller.state_key,
            },
            "topology": None,
            "actors": None,
            "artifacts": None,
            "secret_references": {"value_material_recorded": False, "parameters": []},
            "rollout": {
                "order": [],
                "read_only_validated_at": None,
                "active_promoted_at": None,
                "exact_route_table_arns": [],
            },
            "faults": {"router": None, "leader": None},
            "observations": [],
            "fresh_flows": [],
            "established_flows": [],
            "control_plane": {
                "stale_fence_rejection": None,
                "ambiguous_settlement": None,
            },
            "mutation_audit": self.adapter.ledger.evidence(self.runner_identity),
            "cleanup": {
                "attempted": False,
                "status": "not-required",
                "sequence": [],
                "controller_quiesced": False,
                "controller_destroyed": False,
                "material_deleted": False,
                "appliance_destroyed": False,
                "tailnet_cleaned": False,
                "backend_finalized": False,
                "audits": [],
                "residual_count": 0,
                "errors": [],
            },
            "failure": None,
        }

    def _begin_cleanup_atomically(
        self,
    ) -> HardTimeout | TerminationRequested | None:
        deferred: HardTimeout | TerminationRequested | None = None
        while True:
            try:
                self.begin_cleanup()
                return deferred
            except (HardTimeout, TerminationRequested) as error:
                deferred = deferred or error

    def run(self) -> RunResult:
        evidence = self._initial_evidence()
        stage = "prepare"
        active_attempted = False
        active_succeeded = False
        acceptance_succeeded = False
        cleanup_armed = False
        cleanup_lifecycle_error: HardTimeout | CleanupTimeout | TerminationRequested | None = None
        try:
            capabilities = _mapping(
                self.adapter.conformance_capabilities(),
                "adapter conformance capabilities",
            )
            _exact_keys(
                capabilities,
                set(REQUIRED_SCENARIO_CAPABILITIES),
                "adapter conformance capabilities",
            )
            unsupported = [
                name
                for name in REQUIRED_SCENARIO_CAPABILITIES
                if capabilities[name] is not True
            ]
            if unsupported:
                raise ContractError(
                    "live adapter lacks deterministic conformance prerequisites: "
                    + ", ".join(unsupported)
                )
            stage = "acquire-backend-claim"
            claimed_value = self.adapter.acquire_backend_claim()
            cleanup_armed = True
            claimed = _mapping(claimed_value, "adapter backend claim result")
            _exact_keys(claimed, {"runner_identity"}, "adapter backend claim result")
            self.runner_identity = cast(Mapping[str, str], claimed["runner_identity"])

            stage = "prepare"
            prepared = _mapping(self.adapter.prepare(), "adapter prepare result")
            _exact_keys(prepared, set(), "adapter prepare result")

            stage = "deploy-appliance"
            self.adapter.deploy_appliance()
            stage = "prepare-controller"
            controller = _mapping(self.adapter.prepare_controller(), "adapter controller preparation")
            _exact_keys(
                controller,
                {"topology", "artifacts", "secret_references"},
                "adapter controller preparation",
            )
            evidence["topology"] = copy.deepcopy(controller["topology"])
            evidence["artifacts"] = copy.deepcopy(controller["artifacts"])
            evidence["secret_references"] = copy.deepcopy(controller["secret_references"])

            stage = "deploy-read-only"
            read_only = _mapping(self.adapter.deploy_controller("read-only"), "read-only deployment")
            _exact_keys(
                read_only,
                {"mode", "exact_route_table_arns", "actors"},
                "read-only deployment",
            )
            if (
                read_only["mode"] != "read-only"
                or read_only["exact_route_table_arns"] != []
            ):
                raise ContractError("read-only deployment unexpectedly has route mutation authority")
            evidence["actors"] = copy.deepcopy(read_only["actors"])
            evidence["rollout"]["order"].append("read-only-deployed")
            stage = "validate-read-only-cold"
            cold = [
                validate_observation(item, expected_stage="read-only-cold")
                for item in self.adapter.wait_observation("read-only-cold", {})
            ]
            if not cold or any(item["dynamodb"]["present"] for item in cold):
                raise ContractError("read-only rollout did not retain an empty durable cold state")
            evidence["observations"].extend(cold)
            evidence["rollout"]["read_only_validated_at"] = max(
                item["captured_at"] for item in cold
            )
            evidence["rollout"]["order"].append("read-only-cold-validated")

            stage = "promote-active"
            active_attempted = True
            active = _mapping(self.adapter.deploy_controller("active"), "active deployment")
            _exact_keys(
                active,
                {"mode", "exact_route_table_arns", "actors"},
                "active deployment",
            )
            if active["mode"] != "active" or not active["exact_route_table_arns"]:
                raise ContractError("active deployment omitted exact route IAM authority")
            if active["actors"] != evidence["actors"]:
                raise ContractError("controller actor identities changed during active promotion")
            active_succeeded = True
            evidence["rollout"]["active_promoted_at"] = self.now()
            evidence["rollout"]["exact_route_table_arns"] = sorted(active["exact_route_table_arns"])
            evidence["rollout"]["order"].append("active-promoted")

            stage = "observe-active-baseline"
            baseline = [
                validate_observation(item, expected_stage="active-baseline")
                for item in self.adapter.wait_observation("active-baseline", {})
            ]
            evidence["observations"].extend(baseline)
            selection = dict(self.adapter.select_domain(baseline))
            _exact_keys(
                selection,
                {"domain_id", "router_id", "alternate_router_id"},
                "selected failover domain",
            )

            stage = "observe-lease-renewal"
            renewal = [
                validate_observation(item, expected_stage="lease-renewal")
                for item in self.adapter.wait_observation(
                    "lease-renewal", {**selection, "baseline": baseline}
                )
            ]
            evidence["observations"].extend(renewal)

            stage = "start-established-flows"
            established_handle = dict(self.adapter.start_established_flows(selection))
            stage = "inject-router-failure"
            router_fault = dict(self.adapter.inject_router_failure(selection))
            evidence["faults"]["router"] = router_fault
            stage = "observe-observer-disagreement"
            disagreement = [
                validate_observation(item, expected_stage="observer-disagreement")
                for item in self.adapter.wait_observation(
                    "observer-disagreement",
                    {**selection, "router_fault": router_fault, "baseline": baseline},
                )
            ]
            evidence["observations"].extend(disagreement)
            stage = "observe-route-progress"
            progress = [
                validate_observation(item, expected_stage="route-progress")
                for item in self.adapter.wait_observation(
                    "route-progress", {**selection, "router_fault": router_fault}
                )
            ]
            evidence["observations"].extend(progress)
            selected_progress = next(
                item for item in progress if item["domain_id"] == selection["domain_id"]
            )
            stage = "inject-controller-leader-failure"
            leader_fault = dict(
                self.adapter.inject_leader_failure(selection, selected_progress)
            )
            stage = "observe-leader-handoff"
            handoff = [
                validate_observation(item, expected_stage="leader-handoff")
                for item in self.adapter.wait_observation(
                    "leader-handoff", {**selection, "leader_fault": leader_fault}
                )
            ]
            evidence["observations"].extend(handoff)
            selected_handoff = next(
                item for item in handoff if item["domain_id"] == selection["domain_id"]
            )
            leader_fault["new_controller_id"] = selected_handoff["dynamodb"]["lease_holder"]
            leader_fault["new_fence"] = selected_handoff["dynamodb"]["fence_term"]
            evidence["faults"]["leader"] = leader_fault

            stage = "observe-router-failover"
            failover = [
                validate_observation(item, expected_stage="router-failover")
                for item in self.adapter.wait_observation(
                    "router-failover", {**selection, "router_fault": router_fault}
                )
            ]
            evidence["observations"].extend(failover)
            selected_failover = next(
                item for item in failover if item["domain_id"] == selection["domain_id"]
            )
            stage = "classify-established-flows"
            evidence["established_flows"].extend(
                validate_established_flow(flow)
                for flow in self.adapter.finish_established_flows(
                    established_handle,
                    {
                        "fault_injected_at": str(router_fault["injected_at"]),
                        "convergence_at": str(selected_failover["captured_at"]),
                    },
                )
            )
            stage = "observe-stale-fence-rejection"
            evidence["control_plane"]["stale_fence_rejection"] = copy.deepcopy(
                dict(
                    self.adapter.observe_stale_fence_rejection(
                        selection, leader_fault, selected_handoff
                    )
                )
            )
            stage = "observe-ambiguous-settlement"
            evidence["control_plane"]["ambiguous_settlement"] = copy.deepcopy(
                dict(self.adapter.observe_ambiguous_settlement(selection, selected_handoff))
            )
            stage = "probe-failover-fresh-flows"
            evidence["fresh_flows"].extend(
                validate_flow(flow)
                for flow in self.adapter.probe_fresh_flows(
                    "router-failover",
                    selection,
                    {
                        "event_at": str(router_fault["injected_at"]),
                        "convergence_at": str(selected_failover["captured_at"]),
                    },
                )
            )

            stage = "observe-durable-alternate"
            alternate = [
                validate_observation(item, expected_stage="durable-alternate")
                for item in self.adapter.wait_observation(
                    "durable-alternate", {**selection, "leader_fault": leader_fault}
                )
            ]
            evidence["observations"].extend(alternate)
            stage = "restore-router"
            restoration = dict(self.adapter.restore_router(router_fault))
            _exact_keys(restoration, {"restored_at"}, "router restoration")
            cast(dict[str, Any], evidence["faults"]["router"])["restored_at"] = restoration[
                "restored_at"
            ]

            stage = "observe-failback-gate"
            gate = [
                validate_observation(item, expected_stage="failback-gate")
                for item in self.adapter.wait_observation(
                    "failback-gate", {**selection, "restoration": restoration}
                )
            ]
            evidence["observations"].extend(gate)
            stage = "observe-failback"
            failback = [
                validate_observation(item, expected_stage="failback-stable")
                for item in self.adapter.wait_observation(
                    "failback-stable",
                    {**selection, "restoration": restoration, "gate": gate},
                )
            ]
            evidence["observations"].extend(failback)
            stage = "probe-failback-fresh-flows"
            evidence["fresh_flows"].extend(
                validate_flow(flow)
                for flow in self.adapter.probe_fresh_flows(
                    "failback-stable",
                    selection,
                    {
                        "event_at": str(restoration["restored_at"]),
                        "convergence_at": str(
                            next(
                                item["captured_at"]
                                for item in failback
                                if item["domain_id"] == selection["domain_id"]
                            )
                        ),
                    },
                )
            )
            acceptance_succeeded = True
        except BaseException as error:
            if (
                isinstance(error, BackendClaimUncertain)
                or getattr(self.adapter, "backend_claim_version_id", None) is not None
            ):
                cleanup_armed = True
            evidence["failure"] = {
                "stage": sanitize_text(stage, self.protected_secrets),
                "category": sanitize_text(
                    type(error).__name__, self.protected_secrets
                ),
                "message": sanitize_text(error, self.protected_secrets),
            }
        finally:
            if not cleanup_armed:
                cleanup = copy.deepcopy(evidence["cleanup"])
            else:
                transition_interruption = self._begin_cleanup_atomically()
                if transition_interruption is not None:
                    acceptance_succeeded = False
                    if evidence["failure"] is None:
                        evidence["failure"] = {
                            "stage": "protected-lifecycle",
                            "category": type(transition_interruption).__name__,
                            "message": "protected lifecycle interruption was blocked until cleanup started",
                        }
                try:
                    cleanup = self._cleanup(active_attempted, active_succeeded)
                except (HardTimeout, CleanupTimeout, TerminationRequested) as error:
                    cleanup_lifecycle_error = error
                    cleanup = {
                        "attempted": True,
                        "status": "failed",
                        "sequence": [],
                        "controller_quiesced": False,
                        "controller_destroyed": False,
                        "material_deleted": False,
                        "appliance_destroyed": False,
                        "tailnet_cleaned": False,
                        "backend_finalized": False,
                        "audits": [{"hook": "audit-unavailable", "residual_count": 1}],
                        "residual_count": 1,
                        "errors": [
                            sanitize_text(
                                f"cleanup interrupted: {error}",
                                self.protected_secrets,
                            )
                        ],
                    }
                except BaseException as error:
                    cleanup = {
                        "attempted": True,
                        "status": "failed",
                        "sequence": [],
                        "controller_quiesced": False,
                        "controller_destroyed": False,
                        "material_deleted": False,
                        "appliance_destroyed": False,
                        "tailnet_cleaned": False,
                        "backend_finalized": False,
                        "audits": [{"hook": "audit-unavailable", "residual_count": 1}],
                        "residual_count": 1,
                        "errors": [
                            sanitize_text(
                                f"cleanup aborted: {error}",
                                self.protected_secrets,
                            )
                        ],
                    }
                try:
                    lifecycle = self.finish_cleanup()
                except (HardTimeout, CleanupTimeout, TerminationRequested) as error:
                    if cleanup_lifecycle_error is None:
                        cleanup_lifecycle_error = error
                    lifecycle = {
                        "termination_requested": isinstance(error, TerminationRequested),
                        "acceptance_timed_out": isinstance(error, HardTimeout),
                        "cleanup_timed_out": isinstance(error, CleanupTimeout),
                    }
                    cleanup["status"] = "failed"
                    cleanup["backend_finalized"] = False
                    cleanup["errors"].append(
                        sanitize_text(
                            f"protected-lifecycle: {error}", self.protected_secrets
                        )
                    )
                if lifecycle.get("cleanup_timed_out"):
                    cleanup["status"] = "failed"
                    cleanup["backend_finalized"] = False
                    cleanup["errors"].append(
                        "protected-lifecycle: cleanup deadline elapsed during timer handoff"
                    )
                if lifecycle.get("termination_requested") or lifecycle.get(
                    "acceptance_timed_out"
                ):
                    acceptance_succeeded = False
                    if evidence["failure"] is None:
                        evidence["failure"] = {
                            "stage": "protected-lifecycle",
                            "category": "TerminationRequested"
                            if lifecycle.get("termination_requested")
                            else "HardTimeout",
                            "message": "protected lifecycle interruption was deferred until cleanup completed",
                        }
                if cleanup_lifecycle_error is not None and evidence["failure"] is None:
                    evidence["failure"] = {
                        "stage": "protected-cleanup",
                        "category": type(cleanup_lifecycle_error).__name__,
                        "message": sanitize_text(
                            cleanup_lifecycle_error, self.protected_secrets
                        ),
                    }
            evidence["cleanup"] = cleanup
            evidence["mutation_audit"] = self.adapter.ledger.evidence(self.runner_identity)
            evidence["completed_at"] = self.now()
            evidence["status"] = (
                "passed"
                if acceptance_succeeded
                and cleanup["status"] == "complete"
                and not self.adapter.ledger.denied_attempts
                else "failed"
            )
            if evidence["status"] == "passed":
                try:
                    verify_evidence(evidence)
                except (HardTimeout, CleanupTimeout, TerminationRequested):
                    raise
                except BaseException as error:
                    evidence["status"] = "failed"
                    evidence["failure"] = {
                        "stage": "verify-evidence",
                        "category": sanitize_text(
                            type(error).__name__, self.protected_secrets
                        ),
                        "message": sanitize_text(error, self.protected_secrets),
                    }
            if findings := scan_evidence(evidence, self.protected_secrets):
                raise EvidenceError(
                    "refusing to persist unsafe evidence: " + "; ".join(findings)
                )
            validate_evidence(evidence)
            write_private_json(self.evidence_path, evidence)
        if cleanup_lifecycle_error is not None:
            raise cleanup_lifecycle_error
        if evidence["cleanup"]["status"] == "not-required":
            return RunResult(EXIT_ACCEPTANCE_FAILED, evidence)
        if evidence["cleanup"]["status"] != "complete":
            return RunResult(EXIT_CLEANUP_FAILED, evidence)
        if evidence["status"] != "passed":
            return RunResult(EXIT_ACCEPTANCE_FAILED, evidence)
        return RunResult(EXIT_OK, evidence)

    def _cleanup(self, active_attempted: bool, active_succeeded: bool) -> dict[str, Any]:
        cleanup: dict[str, Any] = {
            "attempted": True,
            "status": "failed",
            "sequence": [],
            "controller_quiesced": False,
            "controller_destroyed": False,
            "material_deleted": False,
            "appliance_destroyed": False,
            "tailnet_cleaned": False,
            "backend_finalized": False,
            "audits": [],
            "residual_count": 0,
            "errors": [],
        }
        def invoke(name: str, operation: Callable[[], Mapping[str, Any]]) -> bool:
            cleanup["sequence"].append(name)
            try:
                result = _mapping(operation(), f"cleanup {name}")
                if result.get("complete") is not True:
                    raise ContractError(f"cleanup {name} did not return complete=true")
                return True
            except (HardTimeout, CleanupTimeout, TerminationRequested):
                raise
            except BaseException as error:
                cleanup["errors"].append(
                    sanitize_text(f"{name}: {error}", self.protected_secrets)
                )
                return False

        def skip(name: str, reason: str) -> bool:
            cleanup["sequence"].append(name)
            cleanup["errors"].append(f"{name}: skipped {reason}")
            return False

        faults_ok = invoke("restore-faults", self.adapter.restore_faults_for_cleanup)
        quiesced = invoke(
            "quiesce-controller",
            lambda: self.adapter.quiesce_controller(
                active_attempted, active_succeeded
            ),
        )
        cleanup["controller_quiesced"] = quiesced
        controller_destroyed = (
            invoke("destroy-controller", self.adapter.destroy_controller)
            if quiesced
            else skip("destroy-controller", "because controller quiescence was not proved")
        )
        cleanup["controller_destroyed"] = controller_destroyed
        material_deleted = (
            invoke("delete-controller-material", self.adapter.delete_controller_material)
            if controller_destroyed
            else skip("delete-controller-material", "while a controller may remain")
        )
        cleanup["material_deleted"] = material_deleted
        appliance_destroyed = (
            invoke("destroy-appliance", self.adapter.destroy_appliance)
            if controller_destroyed
            else skip("destroy-appliance", "while a controller may retain route authority")
        )
        cleanup["appliance_destroyed"] = appliance_destroyed
        tailnet_cleaned = (
            invoke("cleanup-tailnet", self.adapter.cleanup_tailnet)
            if appliance_destroyed
            else skip("cleanup-tailnet", "before appliance destruction")
        )
        cleanup["tailnet_cleaned"] = tailnet_cleaned
        cleanup["sequence"].append("audit-zero-residual")
        try:
            audits = [dict(item) for item in self.adapter.audit_residuals()]
            for audit in audits:
                _exact_keys(audit, {"hook", "residual_count"}, "residual audit")
                _string(audit["hook"], "residual audit hook", pattern=_ID_RE)
                _integer(audit["residual_count"], "residual audit count")
            if [audit["hook"] for audit in audits] != list(RESIDUAL_AUDIT_HOOKS):
                raise ContractError("residual audit omitted or reordered an authoritative hook")
            cleanup["audits"] = audits
            cleanup["residual_count"] = sum(item["residual_count"] for item in audits)
            if cleanup["residual_count"]:
                cleanup["errors"].append("audit-zero-residual: live run residuals remain")
        except (HardTimeout, CleanupTimeout, TerminationRequested):
            raise
        except BaseException as error:
            cleanup["errors"].append(
                sanitize_text(
                    f"audit-zero-residual: {error}", self.protected_secrets
                )
            )
            cleanup["audits"] = [{"hook": "audit-unavailable", "residual_count": 1}]
            cleanup["residual_count"] = 1
        backend_finalized = (
            faults_ok
            and quiesced
            and cleanup["residual_count"] == 0
            and controller_destroyed
            and material_deleted
            and appliance_destroyed
            and tailnet_cleaned
            and not cleanup["errors"]
            and invoke("finalize-backend", self.adapter.finalize_backend)
        )
        if cleanup["sequence"][-1] != "finalize-backend":
            cleanup["sequence"].append("finalize-backend")
            cleanup["errors"].append(
                "finalize-backend: skipped until every authoritative residual audit is zero"
            )
        cleanup["backend_finalized"] = backend_finalized
        complete = (
            faults_ok
            and quiesced
            and controller_destroyed
            and material_deleted
            and appliance_destroyed
            and tailnet_cleaned
            and backend_finalized
            and cleanup["residual_count"] == 0
            and not cleanup["errors"]
        )
        cleanup["status"] = "complete" if complete else "failed"
        return cleanup


class GuardedCommandRunner:
    """Command adapter that structurally rejects both forbidden actuator paths."""

    def __init__(self, delegate: SubprocessRunner, ledger: MutationLedger):
        self.delegate = delegate
        self.ledger = ledger

    def run(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: pathlib.Path | None = None,
        input_text: str | None = None,
        timeout_seconds: float | None = None,
        timeout: float | None = None,
    ) -> str:
        lowered = [part.lower() for part in args]
        if lowered and pathlib.Path(lowered[0]).name == "aws":
            forbidden_operations = {
                "associate-route-table": "ec2:AssociateRouteTable",
                "create-route": "ec2:CreateRoute",
                "delete-route": "ec2:DeleteRoute",
                "disassociate-route-table": "ec2:DisassociateRouteTable",
                "replace-route": "ec2:ReplaceRoute",
                "replace-route-table-association": "ec2:ReplaceRouteTableAssociation",
            }
            for index in range(1, len(lowered) - 1):
                if lowered[index] == "ec2" and lowered[index + 1] in forbidden_operations:
                    self.ledger.aws(forbidden_operations[lowered[index + 1]])
        if lowered and pathlib.Path(lowered[0]).name in {"tailscale", "tailscaled"}:
            if any(
                part in {"set", "up", "advertise-routes", "--advertise-routes"}
                or part.startswith("--advertise-routes=")
                for part in lowered[1:]
            ):
                self.ledger.tailnet("tailscale:UpdateAdvertisements")
        return self.delegate.run(
            args,
            env=env,
            cwd=cwd,
            input_text=input_text,
            timeout_seconds=timeout_seconds,
            timeout=timeout,
        )


class BoundedAwsCLI(AwsCLI):
    """AWS CLI adapter with a default deadline for every API invocation."""

    def __init__(
        self,
        runner: GuardedCommandRunner,
        excluded_environment: Sequence[str],
        *,
        default_timeout_seconds: float = 60,
    ):
        super().__init__(runner, excluded_environment)
        self.default_timeout_seconds = default_timeout_seconds

    def call(
        self,
        args: list[str],
        *,
        region: str | None = None,
        timeout_seconds: float | None = None,
        timeout: float | None = None,
    ) -> str:
        if timeout_seconds is None and timeout is None:
            timeout_seconds = self.default_timeout_seconds
        return super().call(
            args,
            region=region,
            timeout_seconds=timeout_seconds,
            timeout=timeout,
        )


class TerraformWorkspace:
    def __init__(
        self,
        config: ProductionRunConfig,
        runner: GuardedCommandRunner,
        run_dir: pathlib.Path,
        source_dir: pathlib.Path,
        name: str,
        state_key: str,
    ):
        self.config = config
        self.runner = runner
        self.run_dir = run_dir
        self.source_dir = source_dir.expanduser().resolve()
        self.name = name
        self.state_key = state_key
        self.data_dir = run_dir / f"terraform-data-{name}"
        self.backend_path = run_dir / f"backend-{name}.hcl"
        self.variables_path = run_dir / f"{name}.tfvars.json"
        self.initialized = False
        self.has_applied = False

    def _environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "TF_DATA_DIR": str(self.data_dir),
                "TF_IN_AUTOMATION": "1",
            }
        )
        return environment

    def initialize(self) -> None:
        if self.initialized:
            return
        if not self.source_dir.is_dir():
            raise ContractError(f"{self.name} Terraform source directory is missing")
        self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        backend = self.config.appliance.backend
        text = "\n".join(
            (
                f'bucket = {json.dumps(backend["bucket"])}',
                f'key = {json.dumps(self.state_key)}',
                f'region = {json.dumps(backend["region"])}',
                f'kms_key_id = {json.dumps(backend["kms_key_arn"])}',
                "encrypt = true",
                "use_lockfile = true",
            )
        ) + "\n"
        self.backend_path.write_text(text, encoding="utf-8")
        os.chmod(self.backend_path, 0o600)
        self.runner.run(
            [
                "terraform",
                "init",
                "-input=false",
                "-reconfigure",
                "-lockfile=readonly",
                f"-backend-config={self.backend_path}",
            ],
            env=self._environment(),
            cwd=self.source_dir,
            timeout_seconds=TERRAFORM_INIT_TIMEOUT_SECONDS,
        )
        self.initialized = True

    def apply(
        self,
        variables: Mapping[str, Any],
        label: str,
        *,
        cleanup: bool = False,
    ) -> dict[str, Any]:
        self.initialize()
        self.variables_path.write_text(
            json.dumps(variables, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        os.chmod(self.variables_path, 0o600)
        plan_path = self.run_dir / f"{self.name}-{label}.tfplan"
        self.runner.run(
            [
                "terraform",
                "plan",
                "-input=false",
                f"-out={plan_path}",
                f"-var-file={self.variables_path}",
            ],
            env=self._environment(),
            cwd=self.source_dir,
            timeout_seconds=(
                TERRAFORM_CLEANUP_PLAN_TIMEOUT_SECONDS
                if cleanup
                else TERRAFORM_PLAN_TIMEOUT_SECONDS
            ),
        )
        os.chmod(plan_path, 0o600)
        self.runner.run(
            ["terraform", "apply", "-input=false", "-auto-approve", str(plan_path)],
            env=self._environment(),
            cwd=self.source_dir,
            timeout_seconds=(
                TERRAFORM_CLEANUP_APPLY_TIMEOUT_SECONDS
                if cleanup
                else TERRAFORM_APPLY_TIMEOUT_SECONDS
            ),
        )
        self.has_applied = True
        output = self.runner.run(
            ["terraform", "output", "-json"],
            env=self._environment(),
            cwd=self.source_dir,
            timeout_seconds=TERRAFORM_OUTPUT_TIMEOUT_SECONDS,
        )
        return _mapping(strict_json_loads(output, f"{self.name} Terraform output"), f"{self.name} Terraform output")

    def destroy(self) -> None:
        if not self.initialized and not self.variables_path.is_file():
            return
        self.initialize()
        if not self.variables_path.is_file():
            return
        plan_path = self.run_dir / f"{self.name}-destroy.tfplan"
        self.runner.run(
            [
                "terraform",
                "plan",
                "-destroy",
                "-input=false",
                f"-out={plan_path}",
                f"-var-file={self.variables_path}",
            ],
            env=self._environment(),
            cwd=self.source_dir,
            timeout_seconds=TERRAFORM_CLEANUP_PLAN_TIMEOUT_SECONDS,
        )
        self.runner.run(
            ["terraform", "apply", "-input=false", "-auto-approve", str(plan_path)],
            env=self._environment(),
            cwd=self.source_dir,
            timeout_seconds=TERRAFORM_CLEANUP_APPLY_TIMEOUT_SECONDS,
        )
        self.has_applied = False


class AwsProductionAdapter:
    """Live adapter. Every I/O boundary is replaceable by the protocol in tests."""

    def __init__(
        self,
        config: ProductionRunConfig,
        run_dir: pathlib.Path,
        appliance_dir: pathlib.Path,
        controller_dir: pathlib.Path,
        *,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.timezone.utc),
    ):
        self.config = config
        self.protected_secrets = protected_environment_secrets(config)
        self.run_dir = run_dir.expanduser().resolve()
        self.run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.invocation_id = hashlib.sha256(os.urandom(32)).hexdigest()
        session_deny = os.environ.get(RUNNER_DENY_ENV) == "true"
        self.ledger = MutationLedger(session_deny=session_deny)
        excluded = (
            *config.appliance.oauth_environment_names,
            CONTROLLER_TSNET_ENV,
            CONTROLLER_ADMIN_ENV,
        )
        delegate = SubprocessRunner(excluded)
        self.command = GuardedCommandRunner(delegate, self.ledger)
        self.aws = BoundedAwsCLI(self.command, excluded)
        self.tailnet = build_tailscale(config.appliance)
        self.appliance_workspace = TerraformWorkspace(
            config,
            self.command,
            self.run_dir,
            appliance_dir,
            "appliance",
            config.appliance_state_key,
        )
        self.controller_workspace = TerraformWorkspace(
            config,
            self.command,
            self.run_dir,
            controller_dir,
            "controller",
            config.controller.state_key,
        )
        self.sleep = sleep
        self.monotonic = monotonic
        self.wall_clock = wall_clock
        self.runner_identity: dict[str, str] | None = None
        self.packet_artifact: dict[str, Any] | None = None
        self.controller_manifest: dict[str, Any] | None = None
        self.router_key_id: str | None = None
        self.created_auth_key_ids: list[str] = []
        self.router_parameters: list[dict[str, str]] = []
        self.controller_parameters: list[dict[str, str]] = []
        self.uploaded_objects: list[dict[str, Any]] = []
        self.tailnet_baseline_captured = False
        self.tailnet_device_baseline_ids: set[str] = set()
        self.tailnet_auth_key_baseline_ids: set[str] = set()
        self.tailnet_owned_device_ids: set[str] = set()
        self.router_auth_key_description = (
            f"Envelope production controller acceptance {self.config.run_id}"
        )
        self.deployment: ApplianceDeployment | None = None
        self.topology: dict[str, Any] | None = None
        self.topology_identity: dict[str, Any] | None = None
        self.router_nodes: dict[str, dict[str, Any]] = {}
        self.controller_variables: dict[str, Any] | None = None
        self.controller_output: dict[str, Any] | None = None
        self.controller_mode: str | None = None
        self.failed_router_id: str | None = None
        self.failed_router_instance: str | None = None
        self.router_restoration_phase: str | None = None
        self.failed_controller_id: str | None = None
        self.failed_controller_instance: str | None = None
        self.controller_restoration_phase: str | None = None
        self.established_commands: dict[str, tuple[str, str]] = {}
        self.appliance_deployment_started = False
        self.active_deployment_attempted = False
        self.backend_claim_key = (
            f"runs/{self.config.run_id}/production-controller-run.claim.json"
        )
        self.backend_claim_version_id: str | None = None
        self.backend_state_cleanup_authorized = False

    def conformance_capabilities(self) -> Mapping[str, bool]:
        # These are capabilities of the old combined-evidence schema, not a
        # requirement to add production fault-injection endpoints. The approved
        # replacement keeps deterministic cases in the Go harness. Until the
        # evidence schema and credential handoff are split, remain blocked.
        return {
            "observer-disagreement": False,
            "lease-renewal": True,
            "in-progress-leader-failure": False,
            "stale-fence-rejection": False,
            "ambiguous-settlement": False,
        }

    def _require_authorized_environment(self) -> None:
        approved = os.environ.get("ENVELOPE_E2E_APPROVED_RUN_ID", "")
        if approved != self.config.run_id or _RUN_RE.fullmatch(approved) is None:
            raise ContractError("protected run ID does not match the environment approval")
        if os.environ.get("GITHUB_ACTIONS") == "true":
            if (
                os.environ.get("GITHUB_HEAD_REPO_FORK") != "false"
                or os.environ.get("GITHUB_REF_PROTECTED") != "true"
                or os.environ.get("GITHUB_EVENT_NAME") not in {"workflow_dispatch", "schedule"}
            ):
                raise ContractError("live execution requires a protected non-fork GitHub ref")
        if not self.ledger.session_deny:
            raise ContractError(
                "the runner AWS session does not declare the explicit route and association mutation deny"
            )

    def _require_toolchain(self) -> None:
        version = _mapping(
            strict_json_loads(
                self.command.run(["terraform", "version", "-json"], timeout_seconds=30),
                "Terraform version",
            ),
            "Terraform version",
        )
        if version.get("terraform_version") != TERRAFORM_VERSION:
            raise ContractError(f"protected run requires Terraform {TERRAFORM_VERSION}")
        expected_machine = {"amd64": "x86_64", "arm64": "aarch64"}[
            self.config.appliance.architecture
        ]
        if platform.system() != "Linux" or platform.machine() != expected_machine:
            raise ContractError("live topology identity generation requires a matching Linux architecture")

    def _build_artifacts(self) -> None:
        output_dir = self.config.appliance.artifact_manifest.parent.resolve()
        expected_manifest = output_dir / "manifest.json"
        if self.config.appliance.artifact_manifest != expected_manifest:
            raise ContractError("artifact_manifest must be the run build directory's manifest.json")
        output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        repository = pathlib.Path(__file__).resolve().parents[1]
        self.command.run(
            [
                str(repository / "scripts" / "build_artifacts.sh"),
                "--output-dir",
                str(output_dir),
                "--architectures",
                self.config.appliance.architecture,
            ],
            cwd=repository,
            timeout_seconds=1800,
        )
        self.command.run(
            [
                str(repository / "scripts" / "build_controller_artifacts.sh"),
                "--output-dir",
                str(output_dir),
                "--version",
                self.config.controller.artifact_version,
                "--architectures",
                self.config.appliance.architecture,
            ],
            cwd=repository,
            timeout_seconds=1800,
        )
        self.packet_artifact = validate_artifact(self.config.appliance)
        manifest_path = output_dir / "controller-manifest.json"
        manifest = _mapping(load_json(manifest_path, "controller artifact manifest"), "controller artifact manifest")
        expected_fields = {
            "schema",
            "component",
            "version",
            "revision",
            "source_dirty",
            "source_date_epoch",
            "build_date",
            "go_version",
            "artifacts",
        }
        _exact_keys(manifest, expected_fields, "controller artifact manifest")
        if (
            manifest["schema"] != 1
            or manifest["component"] != "envelope-controller"
            or manifest["source_dirty"] is not False
            or manifest["version"] != self.config.controller.artifact_version
            or not isinstance(manifest["artifacts"], list)
        ):
            raise ContractError("controller artifact manifest is not one clean reviewed release")
        selected = [
            entry
            for entry in manifest["artifacts"]
            if isinstance(entry, Mapping)
            and entry.get("architecture") == self.config.appliance.architecture
            and entry.get("component") in {"envelope-controller", "envelope-controller-topology"}
        ]
        if {entry.get("component") for entry in selected} != {
            "envelope-controller",
            "envelope-controller-topology",
        } or len(selected) != 2:
            raise ContractError("controller manifest does not contain both selected components")
        self.controller_manifest = manifest

    def _put_parameter(
        self,
        *,
        purpose: str,
        name: str,
        region: str,
        kms_key_arn: str,
        value: str,
    ) -> dict[str, str]:
        if not value or value != value.strip() or len(value) > 4096 or "\n" in value:
            raise ContractError(f"{purpose} protected value is empty or malformed")
        assert self.runner_identity is not None
        account = self.runner_identity["account_id"]
        reference = {
            "purpose": purpose,
            "name": name,
            "arn": f"arn:aws:ssm:{region}:{account}:parameter{name}",
            "kms_key_arn": kms_key_arn,
            "region": region,
            "invocation_id": self.invocation_id,
            "put_outcome": "pending",
        }
        journal = (
            self.router_parameters
            if purpose.startswith("router-")
            else self.controller_parameters
        )
        if any(item["name"] == name and item["region"] == region for item in journal):
            raise ContractError("protected parameter intent was already journaled")
        journal.append(reference)
        payload = {
            "Name": name,
            "Description": f"Ephemeral Envelope protected controller acceptance {self.config.run_id}",
            "Value": value,
            "Type": "SecureString",
            "KeyId": kms_key_arn,
            "Overwrite": False,
            "Tier": "Standard",
            "DataType": "text",
            "Tags": [
                {"Key": "EnvelopeRun", "Value": self.config.run_id},
                {"Key": "ExpiresAt", "Value": self.config.expires_at},
                {"Key": "Purpose", "Value": purpose},
                {"Key": "EnvelopeInvocation", "Value": self.invocation_id},
            ],
        }
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{purpose}-", suffix=".json", dir=self.run_dir
        )
        temporary = pathlib.Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, separators=(",", ":"))
            os.chmod(temporary, 0o600)
            try:
                response = self.aws.json(
                    [
                        "ssm",
                        "put-parameter",
                        "--cli-input-json",
                        f"file://{temporary}",
                    ],
                    region=region,
                )
            except BaseException:
                reference["put_outcome"] = "ambiguous"
                raise
            version = response.get("Version")
            if isinstance(version, bool) or not isinstance(version, int) or version < 1:
                reference["put_outcome"] = "ambiguous"
                raise ContractError(
                    "SSM parameter creation did not return an exact version"
                )
            reference["version"] = str(version)
            reference["put_outcome"] = "confirmed"
            self._wait_parameter_resolution(reference, require_owned=True)
        finally:
            payload["Value"] = ""
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return reference

    def _owned_parameter_exists(
        self,
        reference: Mapping[str, str],
        *,
        deadline: float | None = None,
    ) -> bool:
        monotonic = getattr(self, "monotonic", time.monotonic)

        def query(args: list[str]) -> dict[str, Any]:
            timeout_seconds: float | None = None
            if deadline is not None:
                timeout_seconds = deadline - monotonic()
                if timeout_seconds <= 0:
                    raise RuntimeError("SSM parameter reconciliation deadline elapsed")
            return self.aws.json(
                args,
                region=reference["region"],
                timeout_seconds=timeout_seconds,
            )

        response = query(
            [
                "ssm",
                "describe-parameters",
                "--parameter-filters",
                f"Key=Name,Option=Equals,Values={reference['name']}",
            ]
        )
        values = response.get("Parameters")
        if not isinstance(values, list):
            raise ContractError("SSM parameter ownership query returned an invalid list")
        matches = [
            item
            for item in values
            if isinstance(item, Mapping) and item.get("Name") == reference["name"]
        ]
        if not matches:
            if values:
                raise ContractError("SSM parameter ownership query returned a foreign name")
            return False
        if len(matches) != 1 or len(values) != 1:
            raise ContractError("SSM parameter ownership query was ambiguous")
        parameter = matches[0]
        version = parameter.get("Version")
        if (
            parameter.get("Type") != "SecureString"
            or parameter.get("KeyId") != reference["kms_key_arn"]
            or parameter.get("ARN") not in {None, reference["arn"]}
            or isinstance(version, bool)
            or not isinstance(version, int)
            or version < 1
        ):
            raise ContractError("SSM parameter intent resolved to foreign metadata")
        tags_response = query(
            [
                "ssm",
                "list-tags-for-resource",
                "--resource-type",
                "Parameter",
                "--resource-id",
                reference["name"],
            ]
        )
        tags_value = tags_response.get("TagList")
        if not isinstance(tags_value, list):
            raise ContractError("SSM parameter tag query returned an invalid list")
        tags: dict[str, str] = {}
        for item in tags_value:
            if (
                not isinstance(item, Mapping)
                or not isinstance(item.get("Key"), str)
                or not isinstance(item.get("Value"), str)
                or item["Key"] in tags
            ):
                raise ContractError("SSM parameter tag query returned malformed tags")
            tags[str(item["Key"])] = str(item["Value"])
        if tags != {
            "EnvelopeRun": self.config.run_id,
            "ExpiresAt": self.config.expires_at,
            "Purpose": reference["purpose"],
            "EnvelopeInvocation": reference["invocation_id"],
        }:
            raise ContractError("SSM parameter intent does not have exact run ownership tags")
        expected_version = reference.get("version")
        if expected_version is not None and expected_version != str(version):
            raise ContractError(
                "SSM parameter version changed after invocation-bound creation"
            )
        if expected_version is None and isinstance(reference, dict):
            reference["version"] = str(version)
        return True

    def _wait_parameter_resolution(
        self,
        reference: Mapping[str, str],
        *,
        require_owned: bool | None = None,
    ) -> bool:
        monotonic = getattr(self, "monotonic", time.monotonic)
        sleep = getattr(self, "sleep", time.sleep)
        deadline = monotonic() + SSM_PARAMETER_RECONCILE_TIMEOUT_SECONDS
        stable_state: bool | None = None
        stable_reads = 0
        stable_since = monotonic()
        while True:
            try:
                state = self._owned_parameter_exists(reference, deadline=deadline)
            except (HardTimeout, CleanupTimeout, TerminationRequested):
                raise
            except ContractError:
                raise
            except RuntimeError:
                state = None
            now = monotonic()
            if state is None:
                stable_state = None
                stable_reads = 0
                stable_since = now
            elif state != stable_state:
                stable_state = state
                stable_reads = 1
                stable_since = now
            else:
                stable_reads += 1
            if stable_reads >= SSM_PARAMETER_STABLE_READS:
                if state is True and require_owned is not False:
                    return True
                if (
                    state is False
                    and require_owned is not True
                    and now - stable_since >= SSM_PARAMETER_STABLE_ABSENCE_SECONDS
                ):
                    return False
            if now >= deadline:
                expectation = (
                    "ownership"
                    if require_owned is True
                    else "absence"
                    if require_owned is False
                    else "visibility or absence"
                )
                raise ContractError(
                    f"could not prove stable SSM parameter {expectation} within the bounded reconciliation window"
                )
            sleep(min(SSM_PARAMETER_POLL_SECONDS, max(0.0, deadline - now)))

    def _delete_parameter(self, reference: Mapping[str, str]) -> None:
        if not self._wait_parameter_resolution(reference):
            return
        deletion_error: RuntimeError | None = None
        try:
            self.aws.json(
                ["ssm", "delete-parameter", "--name", reference["name"]],
                region=reference["region"],
                timeout_seconds=SSM_PARAMETER_RECONCILE_TIMEOUT_SECONDS,
            )
        except (HardTimeout, CleanupTimeout, TerminationRequested):
            raise
        except RuntimeError as error:
            if "ParameterNotFound" not in str(error):
                deletion_error = error
        try:
            self._wait_parameter_resolution(reference, require_owned=False)
        except ContractError as error:
            if deletion_error is not None:
                raise ContractError(
                    "ambiguous SSM parameter deletion did not reach stable absence"
                ) from error
            raise

    def _parameter_residual_count(self) -> int:
        return sum(
            int(self._wait_parameter_resolution(reference))
            for reference in [*self.router_parameters, *self.controller_parameters]
        )

    def _backend_state_keys(self) -> tuple[str, ...]:
        return (
            self.config.controller.state_key,
            self.config.controller.state_key + ".tflock",
            self.config.appliance_state_key,
            self.config.appliance_state_key + ".tflock",
        )

    def _require_backend_claim(self) -> tuple[str, str, str, str]:
        version_id = getattr(self, "backend_claim_version_id", None)
        if version_id is None:
            raise ContractError(
                "backend finalization requires this invocation's exact run claim"
            )
        backend = self.config.appliance.backend
        bucket = str(backend["bucket"])
        region = str(backend["region"])
        claim_key = self.backend_claim_key
        versions = exact_object_versions(
            self.aws, bucket=bucket, key=claim_key, region=region
        )
        if versions != [{"version_id": version_id, "kind": "version"}]:
            raise ContractError(
                "backend run claim no longer belongs exclusively to this invocation"
            )
        return bucket, region, claim_key, version_id

    def _release_backend_claim(self) -> None:
        version_id = getattr(self, "backend_claim_version_id", None)
        if version_id is None:
            return
        backend = self.config.appliance.backend
        bucket = str(backend["bucket"])
        region = str(backend["region"])
        self.aws.json(
            [
                "s3api",
                "delete-object",
                "--bucket",
                bucket,
                "--key",
                self.backend_claim_key,
                "--version-id",
                version_id,
            ],
            region=region,
        )
        remaining = exact_object_versions(
            self.aws, bucket=bucket, key=self.backend_claim_key, region=region
        )
        if any(version["version_id"] == version_id for version in remaining):
            raise ContractError("the invocation's exact backend claim version remains")
        self.backend_claim_version_id = None
        self.backend_state_cleanup_authorized = False

    def _require_fresh_local_terraform(self) -> None:
        stale = [
            path
            for workspace in (self.appliance_workspace, self.controller_workspace)
            for path in (workspace.variables_path, workspace.data_dir)
            if path.exists() or path.is_symlink()
        ]
        if stale:
            raise ContractError(
                "run-scoped local Terraform variables or data already exist; refusing run-ID reuse"
            )

    def _configured_tailnet_device_names(self) -> set[str]:
        return {
            *self.config.controller.controller_ids,
            *(
                f"{self.config.run_id}-{site}-transport-{az_key}"
                for site in ("west", "east")
                for az_key in self.config.appliance.sites[site][
                    "transport_router_az_keys"
                ]
            ),
        }

    @staticmethod
    def _tailnet_ids(values: Sequence[Mapping[str, Any]], label: str) -> set[str]:
        identifiers = {
            _string(value.get("id"), f"{label} ID") for value in values
        }
        if len(identifiers) != len(values):
            raise ContractError(f"{label} IDs must be unique")
        return identifiers

    def _capture_tailnet_baseline(self) -> None:
        if self.tailnet_baseline_captured:
            raise ContractError("Tailnet baseline was already captured")
        self.ledger.tailnet("tailscale:ListDevices")
        devices = self.tailnet.list_devices()
        self.ledger.tailnet("tailscale:ListAuthKeys")
        auth_keys = self.tailnet.list_auth_keys()
        expected_names = self._configured_tailnet_device_names()
        if any(
            str(device.get("hostname") or device.get("name") or "").split(".")[0]
            in expected_names
            for device in devices
        ):
            raise ContractError(
                "Tailnet baseline already contains an exact protected run device name"
            )
        if any(
            key.get("description") == self.router_auth_key_description
            for key in auth_keys
        ):
            raise ContractError(
                "Tailnet baseline already contains the exact protected run auth-key description"
            )
        self.tailnet_device_baseline_ids = self._tailnet_ids(
            devices, "Tailnet baseline device"
        )
        self.tailnet_auth_key_baseline_ids = self._tailnet_ids(
            auth_keys, "Tailnet baseline auth key"
        )
        self.tailnet_baseline_captured = True

    def _post_baseline_tailnet_devices(
        self, devices: Sequence[Mapping[str, Any]]
    ) -> list[Mapping[str, Any]]:
        if not self.tailnet_baseline_captured:
            return []
        expected_names = self._expected_tailnet_device_names()
        required_tag = self.config.appliance.tailnet["tag"]
        selected: list[Mapping[str, Any]] = []
        for device in devices:
            device_id = _string(device.get("id"), "Tailnet device ID")
            hostname = str(device.get("hostname") or device.get("name") or "").split(
                "."
            )[0]
            tags = device.get("tags")
            if (
                device_id not in self.tailnet_device_baseline_ids
                and hostname in expected_names
                and isinstance(tags, list)
                and len(tags) == 1
                and tags[0] == required_tag
            ):
                selected.append(device)
        self._tailnet_ids(selected, "run-owned Tailnet device")
        return selected

    def _post_baseline_auth_key_ids(
        self, auth_keys: Sequence[Mapping[str, Any]]
    ) -> set[str]:
        if not self.tailnet_baseline_captured:
            return set()
        required_tag = self.config.appliance.tailnet["tag"]

        def has_exact_capability(key: Mapping[str, Any]) -> bool:
            capabilities = key.get("capabilities")
            devices = (
                capabilities.get("devices")
                if isinstance(capabilities, Mapping)
                else None
            )
            create = devices.get("create") if isinstance(devices, Mapping) else None
            return bool(
                isinstance(create, Mapping)
                and create.get("reusable") is True
                and create.get("ephemeral") is True
                and create.get("preauthorized") is True
                and create.get("tags") == [required_tag]
            )

        return {
            _string(key.get("id"), "run-owned Tailnet auth-key ID")
            for key in auth_keys
            if key.get("description") == self.router_auth_key_description
            and key.get("id") not in self.tailnet_auth_key_baseline_ids
            and has_exact_capability(key)
        }

    def _read_backend_claim_version(
        self,
        *,
        bucket: str,
        region: str,
        version_id: str,
    ) -> bytes:
        temporary_directory = pathlib.Path(
            tempfile.mkdtemp(prefix=".backend-claim-read-", dir=self.run_dir)
        )
        os.chmod(temporary_directory, 0o700)
        temporary = temporary_directory / "claim.json"
        try:
            response = self.aws.json(
                [
                    "s3api",
                    "get-object",
                    "--bucket",
                    bucket,
                    "--key",
                    self.backend_claim_key,
                    "--version-id",
                    version_id,
                    str(temporary),
                ],
                region=region,
            )
            if response.get("VersionId") != version_id:
                raise ContractError(
                    "backend claim read did not return the requested exact version"
                )
            if temporary.is_symlink() or not temporary.is_file():
                raise ContractError("backend claim read did not create one regular file")
            body = temporary.read_bytes()
            if len(body) > MAX_JSON_BYTES:
                raise ContractError("backend claim body exceeds the bounded JSON size")
            return body
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            temporary_directory.rmdir()

    def _reconcile_backend_claim_write(
        self,
        *,
        bucket: str,
        region: str,
        expected_body: bytes,
    ) -> str:
        try:
            versions = exact_object_versions(
                self.aws,
                bucket=bucket,
                key=self.backend_claim_key,
                region=region,
            )
        except BaseException as error:
            raise BackendClaimUncertain(
                "conditional backend claim outcome could not be reconciled"
            ) from error
        if not versions:
            raise BackendClaimUncertain(
                "conditional backend claim outcome has no provable exact version"
            )
        if len(versions) != 1 or versions[0]["kind"] != "version":
            raise BackendClaimUncertain(
                "conditional backend claim outcome has ambiguous object versions"
            )
        version_id = versions[0]["version_id"]
        try:
            body = self._read_backend_claim_version(
                bucket=bucket,
                region=region,
                version_id=version_id,
            )
        except BaseException as error:
            raise BackendClaimUncertain(
                "conditional backend claim body could not be verified"
            ) from error
        if body != expected_body:
            raise ContractError(
                "conditional backend claim belongs to another invocation"
            )
        return version_id

    def _acquire_backend_claim(self) -> None:
        if getattr(self, "backend_claim_version_id", None) is not None:
            raise ContractError("backend run claim was already acquired")
        self.backend_state_cleanup_authorized = False
        backend = self.config.appliance.backend
        bucket = str(backend["bucket"])
        region = str(backend["region"])
        versioning = self.aws.json(
            ["s3api", "get-bucket-versioning", "--bucket", bucket], region=region
        )
        if versioning.get("Status") != "Enabled":
            raise ContractError("backend run claims require enabled S3 versioning")
        protected_keys = (*self._backend_state_keys(), self.backend_claim_key)
        occupied = [
            key
            for key in protected_keys
            if exact_object_versions(self.aws, bucket=bucket, key=key, region=region)
        ]
        if occupied:
            raise ContractError(
                "run-scoped backend state or claim already exists; refusing run-ID reuse"
            )

        assert self.runner_identity is not None
        claim = {
            "schema": 1,
            "kind": "aws-production-controller-run-claim",
            "run_id": self.config.run_id,
            "configuration_sha256": self.config.configuration_sha256,
            "principal_arn_sha256": hash_identity(
                self.runner_identity["principal_arn"]
            ),
            "invocation_id_sha256": hash_identity(self.invocation_id),
            "created_at": utc_now(),
            "nonce_sha256": hashlib.sha256(os.urandom(32)).hexdigest(),
        }
        claim_body = json.dumps(
            claim, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".backend-claim-", suffix=".json", dir=self.run_dir
        )
        temporary = pathlib.Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(claim_body)
            os.chmod(temporary, 0o600)
            write_error: BaseException | None = None
            try:
                response = self.aws.json(
                    [
                        "s3api",
                        "put-object",
                        "--bucket",
                        bucket,
                        "--key",
                        self.backend_claim_key,
                        "--body",
                        str(temporary),
                        "--content-type",
                        "application/json",
                        "--server-side-encryption",
                        "aws:kms",
                    "--ssekms-key-id",
                    str(backend["kms_key_arn"]),
                    "--no-bucket-key-enabled",
                        "--if-none-match",
                        "*",
                    ],
                    region=region,
                )
            except BaseException as error:
                write_error = error
                response = {}
            try:
                version_id = _string(
                    response.get("VersionId"),
                    "backend claim version ID",
                    maximum=1024,
                )
                if version_id == "null":
                    raise ContractError(
                        "backend claim requires S3 bucket versioning"
                    )
            except ContractError as error:
                write_error = write_error or error
                version_id = ""
            ambiguous_write = write_error is not None
            if ambiguous_write:
                reconciled_version = self._reconcile_backend_claim_write(
                    bucket=bucket,
                    region=region,
                    expected_body=claim_body,
                )
                self.backend_claim_version_id = reconciled_version
            else:
                self.backend_claim_version_id = version_id
            try:
                self._require_backend_claim()
                occupied_after_claim = [
                    key
                    for key in self._backend_state_keys()
                    if exact_object_versions(
                        self.aws, bucket=bucket, key=key, region=region
                    )
                ]
                if occupied_after_claim:
                    raise ContractError(
                        "backend state appeared while acquiring the run claim; refusing TOCTOU ownership"
                    )
                self._require_backend_claim()
                self.backend_state_cleanup_authorized = True
            except BaseException:
                try:
                    self._release_backend_claim()
                except BaseException as release_error:
                    raise BackendClaimUncertain(
                        "the exact invocation backend claim could not be safely released"
                    ) from release_error
                raise
            if ambiguous_write:
                raise BackendClaimUncertain(
                    "conditional backend claim response was ambiguous; the exact invocation claim requires cleanup"
                ) from write_error
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def acquire_backend_claim(self) -> Mapping[str, Any]:
        self._require_authorized_environment()
        self._require_toolchain()
        identity = self.aws.json(["sts", "get-caller-identity"])
        account_id = _string(identity.get("Account"), "AWS account ID", pattern=re.compile(r"[0-9]{12}"))
        principal_arn = _string(identity.get("Arn"), "AWS principal ARN")
        session_name = principal_arn.rsplit("/", 1)[-1]
        expected_accounts = {
            self.config.appliance.backend["kms_key_arn"].split(":")[4],
            self.config.controller.secret_kms_key_arn.split(":")[4],
        }
        if expected_accounts != {account_id}:
            raise ContractError("AWS session account differs from configured KMS authority")
        self.runner_identity = {
            "account_id": account_id,
            "principal_arn": principal_arn,
            "session_name": session_name,
        }
        self._require_fresh_local_terraform()
        try:
            self._acquire_backend_claim()
        except BackendClaimUncertain:
            raise
        except BaseException as error:
            if self.backend_claim_version_id is not None:
                raise BackendClaimUncertain(
                    "the exact invocation backend claim may require cleanup"
                ) from error
            raise
        return {"runner_identity": dict(self.runner_identity)}

    def prepare(self) -> Mapping[str, Any]:
        if self.runner_identity is None:
            raise ContractError("mutable preparation requires an acquired backend claim")
        self._require_backend_claim()
        self._build_artifacts()
        tailnet_preflight(self.config.appliance, self.tailnet)
        self._capture_tailnet_baseline()
        self.ledger.tailnet("tailscale:CreateAuthKey")
        try:
            key_id, key_material = self.tailnet.create_auth_key(
                str(self.config.appliance.tailnet["tag"]),
                self.router_auth_key_description,
                int(self.config.appliance.tailnet["auth_key_expiry_seconds"]),
            )
        except BaseException:
            self.ledger.tailnet("tailscale:ListAuthKeys")
            for recovered_id in sorted(
                self._post_baseline_auth_key_ids(self.tailnet.list_auth_keys())
            ):
                if recovered_id not in self.created_auth_key_ids:
                    self.created_auth_key_ids.append(recovered_id)
            raise
        if key_id in self.tailnet_auth_key_baseline_ids:
            key_material = ""
            raise ContractError("Tailnet returned a baseline auth-key ID for this run")
        self.router_key_id = key_id
        self.created_auth_key_ids.append(key_id)
        try:
            for site in ("west", "east"):
                region = str(self.config.appliance.sites[site]["region"])
                self._put_parameter(
                    purpose=f"router-{site}",
                    name=f"/{self.config.run_id}/tailscale-auth",
                    region=region,
                    kms_key_arn=str(
                        self.config.appliance.sites[site]["ssm_kms_key_arn"]
                    ),
                    value=key_material,
                )
        finally:
            key_material = ""
        return {}

    def deploy_appliance(self) -> Mapping[str, Any]:
        if self.packet_artifact is None or len(self.router_parameters) != 2:
            raise ContractError("appliance deployment has not completed protected preparation")
        parameters = [
            {
                "site": reference["purpose"].removeprefix("router-"),
                "arn": reference["arn"],
                "kms_key_arn": reference["kms_key_arn"],
            }
            for reference in self.router_parameters
        ]
        variables = terraform_variables(
            self.config.appliance, self.packet_artifact, parameters
        )
        variables["symmetric_topology"] = copy.deepcopy(
            self.config.raw["symmetric_topology"]
        )
        self.appliance_deployment_started = True
        output = self.appliance_workspace.apply(variables, "create")
        self.deployment = parse_appliance_output(output, self.config)
        if self.deployment.account_id != cast(dict[str, str], self.runner_identity)["account_id"]:
            raise ContractError("appliance output account differs from the protected session")
        return {
            "output_sha256": self.deployment.output_sha256,
            "topology_seed_domains": len(self.deployment.seed.domains),
        }

    def _artifact_version_delta(
        self, artifact: Mapping[str, Any]
    ) -> list[dict[str, str]]:
        try:
            current = exact_object_versions(
                self.aws,
                bucket=str(artifact["bucket"]),
                key=str(artifact["key"]),
                region=str(artifact["region"]),
            )
        except RuntimeError as error:
            if "NoSuchBucket" not in str(error):
                raise
            current = []
        baseline = {
            (str(version["version_id"]), str(version["kind"]))
            for version in cast(Sequence[Mapping[str, str]], artifact["baseline_versions"])
        }
        return [
            version
            for version in current
            if (version["version_id"], version["kind"]) not in baseline
        ]

    def _reconcile_uploaded_artifact(
        self, artifact: dict[str, Any], expected_version_id: str | None = None
    ) -> bool:
        delta = self._artifact_version_delta(artifact)
        if not delta:
            return False
        if len(delta) != 1 or delta[0]["kind"] != "version":
            raise ContractError(
                "controller artifact write has an ambiguous exact version delta"
            )
        version_id = delta[0]["version_id"]
        if expected_version_id is not None and version_id != expected_version_id:
            raise ContractError(
                "controller artifact response differs from its exact version delta"
            )
        artifact["version_id"] = version_id
        return True

    def _upload_artifact(self, entry: Mapping[str, Any]) -> dict[str, Any]:
        assert self.deployment is not None and self.controller_manifest is not None
        output_dir = self.config.appliance.artifact_manifest.parent.resolve()
        component = _string(entry.get("component"), "controller artifact component")
        filename = _string(entry.get("file"), "controller artifact file")
        digest = _string(entry.get("sha256"), "controller artifact SHA", pattern=_SHA_RE)
        path = (output_dir / filename).resolve()
        if path.parent != output_dir or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ContractError("controller artifact bytes differ from the clean manifest")
        key = (
            f"runs/{self.config.run_id}/controller/"
            f"{self.controller_manifest['revision']}/{filename}"
        )
        region = str(self.config.appliance.sites["west"]["region"])
        result: dict[str, Any] = {
            "component": component,
            "bucket": self.deployment.artifact_bucket,
            "key": key,
            "version_id": None,
            "sha256": digest,
            "region": region,
            "baseline_versions": exact_object_versions(
                self.aws,
                bucket=self.deployment.artifact_bucket,
                key=key,
                region=region,
            ),
        }
        self.uploaded_objects.append(result)
        try:
            response = self.aws.json(
                [
                    "s3api",
                    "put-object",
                    "--bucket",
                    self.deployment.artifact_bucket,
                    "--key",
                    key,
                    "--body",
                    str(path),
                    "--server-side-encryption",
                    "AES256",
                    "--metadata",
                    f"sha256={digest}",
                ],
                region=region,
            )
        except BaseException:
            self._reconcile_uploaded_artifact(result)
            raise
        version_id = _string(response.get("VersionId"), "uploaded artifact version ID")
        if version_id == "null":
            raise ContractError("controller artifacts require S3 object versioning")
        if not self._reconcile_uploaded_artifact(result, version_id):
            raise ContractError(
                "controller artifact write is absent from its exact version delta"
            )
        return result

    def _artifact_reference(self, artifact: Mapping[str, Any]) -> dict[str, str]:
        assert self.deployment is not None
        version_id = _string(
            artifact.get("version_id"), "controller artifact version ID"
        )
        bucket_arn = f"arn:aws:s3:::{self.deployment.artifact_bucket}"
        return {
            "region": str(artifact["region"]),
            "bucket_name": str(artifact["bucket"]),
            "bucket_arn": bucket_arn,
            "object_key": artifact["key"],
            "object_arn": f"{bucket_arn}/{artifact['key']}",
            "version_id": version_id,
            "sha256": str(artifact["sha256"]),
        }

    def prepare_controller(self) -> Mapping[str, Any]:
        if self.deployment is None or self.controller_manifest is None:
            raise ContractError("controller preparation requires an applied appliance")
        self.ledger.tailnet("tailscale:ListDevices")
        devices = self.tailnet.list_devices()
        existing_controller_names = {
            str(device.get("hostname") or device.get("name") or "").split(".")[0]
            for device in devices
        }.intersection(self.config.controller.controller_ids)
        if existing_controller_names:
            raise ContractError(
                "Tailnet already contains a configured controller identity before deployment"
            )
        owned_router_devices = self._post_baseline_tailnet_devices(devices)
        authority_table = f"{self.config.run_id}-controller-authority"
        topology, router_nodes = build_controller_topology(
            self.deployment.seed,
            owned_router_devices,
            self.config,
            authority_table,
        )
        self.topology = topology
        self.router_nodes = router_nodes
        self.tailnet_owned_device_ids.update(
            str(identity["device_id"]) for identity in router_nodes.values()
        )
        selected = [
            cast(Mapping[str, Any], entry)
            for entry in self.controller_manifest["artifacts"]
            if isinstance(entry, Mapping)
            and entry.get("architecture") == self.config.appliance.architecture
            and entry.get("component") in {"envelope-controller", "envelope-controller-topology"}
        ]
        uploaded = {str(entry["component"]): self._upload_artifact(entry) for entry in selected}

        topology_path = self.run_dir / "controller-topology.source.json"
        topology_path.write_text(
            json.dumps(topology, sort_keys=True, separators=(",", ":")), encoding="utf-8"
        )
        os.chmod(topology_path, 0o600)
        topology_tool_path = (
            self.config.appliance.artifact_manifest.parent
            / next(
                str(entry["file"])
                for entry in selected
                if entry["component"] == "envelope-controller-topology"
            )
        ).resolve()
        identity_text = self.command.run(
            [str(topology_tool_path), "identity", "--input", str(topology_path)],
            timeout_seconds=60,
        )
        identity = validate_topology_identity(
            strict_json_loads(identity_text, "topology identity"), topology
        )
        self.topology_identity = identity
        identity_path = self.run_dir / "controller-topology-identity.json"
        identity_path.write_text(
            json.dumps(identity, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        os.chmod(identity_path, 0o600)

        for purpose, environment_name in (
            ("controller-tsnet", CONTROLLER_TSNET_ENV),
            ("controller-admin-readonly", CONTROLLER_ADMIN_ENV),
        ):
            secret = os.environ.get(environment_name, "")
            self._put_parameter(
                purpose=purpose,
                name=f"/{self.config.run_id}/{purpose}",
                region=self.config.controller.region,
                kms_key_arn=self.config.controller.secret_kms_key_arn,
                value=secret,
            )
            secret = ""

        parameter_by_purpose = {
            reference["purpose"]: reference for reference in self.controller_parameters
        }
        seed = self.deployment.seed
        account = self.deployment.account_id
        managed_routes: dict[str, dict[str, Any]] = {}
        for domain in seed.domains:
            site = seed.sites[str(domain["site_id"])]
            region = str(site["region"])
            route_table_id = str(domain["route_table_id"])
            managed_routes[str(domain["id"])] = {
                "region": region,
                "vpc_id": site["vpc_id"],
                "route_table_id": route_table_id,
                "route_table_arn": f"arn:aws:ec2:{region}:{account}:route-table/{route_table_id}",
                "gwlbe_subnet_id": domain["gwlbe_subnet_id"],
                "route_table_association_id": domain["route_table_association_id"],
                "source_prefix": domain["source_prefix"],
                "destination_cidrs": domain["remote_prefixes"],
                "eligible_eni_ids": sorted(
                    router["eni_id"]
                    for router in seed.routers
                    if router["site_id"] == domain["site_id"]
                ),
            }
        transport_topology: dict[str, dict[str, Any]] = {}
        for site_id, site in seed.sites.items():
            remote = sorted(
                prefix
                for other_id, other in seed.sites.items()
                if other_id != site_id
                for prefix in other["local_prefixes"]
            )
            transport_topology[site_id] = {
                "local_prefixes": site["local_prefixes"],
                "local_main_rule_priority_base": site["local_main_rule_priority_base"],
                "tailscale_route_rule_priority": site["tailscale_route_rule_priority"],
                "routers": {
                    str(router["id"]): {
                        "stable_node_id": router_nodes[str(router["id"])]["stable_node_id"],
                        "instance_id": router["instance_id"],
                        "eni_id": router["eni_id"],
                        "expected_advertised_prefixes": site["local_prefixes"],
                        "expected_enabled_prefixes": site["local_prefixes"],
                        "expected_accepted_remote_prefixes": remote,
                        "expected_local_main_prefixes": site["local_prefixes"],
                    }
                    for router in seed.routers
                    if router["site_id"] == site_id
                },
            }
        manifest_path = self.config.appliance.artifact_manifest.parent / "controller-manifest.json"
        manifest_text = manifest_path.read_text(encoding="utf-8")
        self.controller_variables = {
            "name": self.config.run_id,
            "aws_region": self.config.controller.region,
            "aws_account_id": account,
            "vpc_id": self.config.controller.vpc_id,
            "controller_ami_id": self.config.controller.ami_id,
            "controller_ami_trusted_owner_ids": list(self.config.controller.ami_trusted_owner_ids),
            "controller_architecture": self.config.appliance.architecture,
            "controller_instance_type": self.config.controller.instance_type,
            "deployment_mode": "read-only",
            "protected_acceptance_mode": True,
            "controller_ids": list(self.config.controller.controller_ids),
            "controller_placements": self.config.controller.placements,
            "management_egress": self.config.controller.management_egress,
            "authority_table_name": authority_table,
            "topology_identity_json": json.dumps(identity, sort_keys=True, separators=(",", ":")),
            "topology_parameter_name": f"/{self.config.run_id}/controller/topology",
            "artifact": self._artifact_reference(uploaded["envelope-controller"]),
            "topology_identity_artifact": self._artifact_reference(
                uploaded["envelope-controller-topology"]
            ),
            "artifact_manifest_json": manifest_text,
            "artifact_manifest_sha256": hashlib.sha256(manifest_text.encode("utf-8")).hexdigest(),
            "secret_parameters": {
                "tsnet": {
                    name: parameter_by_purpose["controller-tsnet"][name]
                    for name in ("name", "arn", "kms_key_arn")
                },
                "admin": {
                    name: parameter_by_purpose["controller-admin-readonly"][name]
                    for name in ("name", "arn", "kms_key_arn")
                },
            },
            "managed_route_tables": managed_routes,
            "transport_topology": transport_topology,
            "metrics_ingress_cidrs": list(self.config.controller.metrics_ingress_cidrs),
            "metrics_port": self.config.controller.metrics_port,
            "readiness_publisher": self.config.controller.readiness_publisher,
            "alarm_actions": list(self.config.controller.alarm_actions),
            "tags": {
                "EnvelopeRun": self.config.run_id,
                "ExpiresAt": self.config.expires_at,
            },
        }
        topology_summary = {
            "schema_version": 1,
            "sha256": identity["canonical_sha256"],
            "source_output_sha256": self.deployment.output_sha256,
            "controller_ids": list(self.config.controller.controller_ids),
            "domain_ids": sorted(str(domain["id"]) for domain in seed.domains),
            "policy": {
                "observation_quorum": self.config.controller.policy["observation_quorum"],
                "observation_freshness_milliseconds": int(
                    self.config.controller.policy_seconds["observation_freshness"] * 1000
                ),
                "lease_renew_interval_milliseconds": int(
                    self.config.controller.policy_seconds["lease_renew_interval"] * 1000
                ),
                "failback_stability_milliseconds": int(
                    self.config.controller.policy_seconds["failback_stability"] * 1000
                ),
                "cooldown_milliseconds": int(
                    self.config.controller.policy_seconds["cooldown"] * 1000
                ),
            },
            "gwlbe_authority": [
                {
                    "domain_id": domain["id"],
                    "site_id": domain["site_id"],
                    "region": seed.sites[str(domain["site_id"])]["region"],
                    "vpc_id": seed.sites[str(domain["site_id"])]["vpc_id"],
                    "route_table_id": domain["route_table_id"],
                    "gwlbe_subnet_id": domain["gwlbe_subnet_id"],
                    "route_table_association_id": domain["route_table_association_id"],
                    "source_prefix": domain["source_prefix"],
                    "remote_prefixes": list(domain["remote_prefixes"]),
                    "preferred_owner": domain["preferred_owner"],
                    "eligible_routers": [
                        {
                            "router_id": router["id"],
                            "instance_id": router["instance_id"],
                            "eni_id": router["eni_id"],
                            "stable_node_sha256": router_nodes[str(router["id"])][
                                "stable_node_sha256"
                            ],
                        }
                        for router in seed.routers
                        if router["site_id"] == domain["site_id"]
                    ],
                }
                for domain in seed.domains
            ],
        }
        artifact_summary = {
            "manifest_sha256": self.controller_variables["artifact_manifest_sha256"],
            "revision": self.controller_manifest["revision"],
            "version": self.controller_manifest["version"],
            "architecture": self.config.appliance.architecture,
            "objects": [
                {
                    name: artifact[name]
                    for name in ("component", "key", "version_id", "sha256")
                }
                for artifact in sorted(self.uploaded_objects, key=lambda item: item["component"])
            ],
        }
        reference_summary = {
            "value_material_recorded": False,
            "parameters": [
                {
                    "purpose": reference["purpose"],
                    "name": reference["name"],
                    "arn": reference["arn"],
                    "kms_key_arn_sha256": hash_identity(reference["kms_key_arn"]),
                }
                for reference in sorted(
                    [*self.router_parameters, *self.controller_parameters],
                    key=lambda item: (item["purpose"], item["region"]),
                )
            ],
        }
        return {
            "topology": topology_summary,
            "artifacts": artifact_summary,
            "secret_references": reference_summary,
        }

    def _controller_actors(
        self, output: Mapping[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        document = output if output is not None else self.controller_output
        if document is None:
            return []
        instances = _mapping(
            _output_value(document, "controller_instances"),
            "controller instances",
        )
        if set(instances) != set(self.config.controller.controller_ids):
            raise ContractError("controller output does not identify exactly every replica")
        actors: list[dict[str, Any]] = []
        for controller_id in self.config.controller.controller_ids:
            instance = _mapping(
                instances[controller_id], f"controller instance {controller_id}"
            )
            _exact_keys(
                instance,
                {
                    "instance_id",
                    "private_ip",
                    "subnet_id",
                    "availability_zone",
                    "observer_volume_id",
                },
                f"controller instance {controller_id}",
            )
            placement = self.config.controller.placements[controller_id]
            address_text = _string(
                instance["private_ip"], f"controller {controller_id} private IP"
            )
            try:
                address = ipaddress.ip_address(address_text)
            except ValueError as error:
                raise ContractError("controller output contains an invalid private IP") from error
            actor = {
                "actor_type": "controller",
                "actor_id": controller_id,
                "instance_id": _string(
                    instance["instance_id"],
                    f"controller {controller_id} instance ID",
                    pattern=_INSTANCE_RE,
                ),
                "region": self.config.controller.region,
                "vpc_id": self.config.controller.vpc_id,
                "subnet_id": _string(
                    instance["subnet_id"],
                    f"controller {controller_id} subnet",
                    pattern=_SUBNET_RE,
                ),
                "availability_zone": _string(
                    instance["availability_zone"],
                    f"controller {controller_id} availability zone",
                    pattern=re.compile(re.escape(self.config.controller.region) + r"[a-z]"),
                ),
                "private_ip": str(address),
            }
            if (
                address.version != 4
                or actor["subnet_id"] != placement["subnet_id"]
                or actor["availability_zone"] != placement["availability_zone"]
            ):
                raise ContractError(
                    "controller output differs from its exact placement authority"
                )
            actors.append(actor)
        return actors

    def _instance_actors(
        self, controller_output: Mapping[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        actors = self._controller_actors(controller_output)
        if self.deployment is not None:
            for site in sorted(self.deployment.workloads):
                for role in sorted(self.deployment.workloads[site]):
                    workload = self.deployment.workloads[site][role]
                    actors.append(
                        {
                            name: workload[name]
                            for name in (
                                "actor_id",
                                "instance_id",
                                "region",
                                "vpc_id",
                                "subnet_id",
                                "availability_zone",
                                "private_ip",
                            )
                        }
                        | {"actor_type": "workload"}
                    )
            for router in self.deployment.seed.routers:
                actors.append(
                    {
                        "actor_type": "router",
                        "actor_id": router["id"],
                        "instance_id": router["instance_id"],
                        "region": router["region"],
                        "vpc_id": router["vpc_id"],
                        "subnet_id": router["subnet_id"],
                        "availability_zone": router["availability_zone"],
                        "private_ip": None,
                    }
                )
        instance_ids = [str(actor["instance_id"]) for actor in actors]
        actor_keys = [
            (str(actor["actor_type"]), str(actor["actor_id"])) for actor in actors
        ]
        if len(set(instance_ids)) != len(instance_ids) or len(set(actor_keys)) != len(
            actor_keys
        ):
            raise ContractError("runtime actor identities are not globally unique")
        return sorted(
            actors, key=lambda actor: (str(actor["actor_type"]), str(actor["actor_id"]))
        )

    def _actor_summary(
        self, controller_output: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        return {"instances": self._instance_actors(controller_output)}

    def _expected_instance_actor(self, instance_id: str, region: str) -> dict[str, Any]:
        matches = [
            actor
            for actor in self._instance_actors()
            if actor["instance_id"] == instance_id and actor["region"] == region
        ]
        if len(matches) != 1:
            raise MutationDenied(
                "EC2 operation target is not one exact protected runtime actor"
            )
        actor = dict(matches[0])
        actor_type = str(actor["actor_type"])
        actor_id = str(actor["actor_id"])
        if actor_type == "controller":
            actor["expected_tags"] = {
                "EnvelopeRun": self.config.run_id,
                "Deployment": self.config.run_id,
                "Name": f"{self.config.run_id}-{actor_id}",
                "Role": "envelope-controller",
                "ControllerID": actor_id,
            }
        elif actor_type == "router":
            router = self.deployment.seed.routers_by_id[actor_id] if self.deployment else {}
            site = str(router["site_id"])
            actor["expected_tags"] = {
                "EnvelopeRun": self.config.run_id,
                "Name": str(router["expected_hostname"]),
                "Role": "transport-router",
                "Site": site,
                "ZoneKey": actor_id.removeprefix(site + "-"),
            }
        else:
            site, role = actor_id.split("-", 1)
            workload = self.deployment.workloads[site][role] if self.deployment else {}
            actor["expected_tags"] = {
                "EnvelopeRun": self.config.run_id,
                "Name": f"{self.config.run_id}-{actor_id}",
                "Role": role,
                "Site": site,
                "ZoneKey": str(workload["az_key"]),
            }
        return actor

    def _describe_instance_actor(
        self,
        instance_id: str,
        region: str,
        *,
        timeout_seconds: float | None = None,
    ) -> tuple[dict[str, Any], str]:
        actor = self._expected_instance_actor(instance_id, region)
        arguments = ["ec2", "describe-instances", "--instance-ids", instance_id]
        response = (
            self.aws.json(
                arguments,
                region=region,
                timeout_seconds=timeout_seconds,
            )
            if timeout_seconds is not None
            else self.aws.json(arguments, region=region)
        )
        reservations = response.get("Reservations")
        instances = [
            instance
            for reservation in reservations
            if isinstance(reservation, Mapping)
            for instance in reservation.get("Instances", [])
            if isinstance(instance, Mapping)
        ] if isinstance(reservations, list) else []
        if len(instances) != 1:
            raise MutationDenied("EC2 actor validation did not return one exact instance")
        instance = instances[0]
        placement = instance.get("Placement")
        state = instance.get("State")
        expected_values = {
            "InstanceId": actor["instance_id"],
            "VpcId": actor["vpc_id"],
            "SubnetId": actor["subnet_id"],
        }
        if actor["private_ip"] is not None:
            expected_values["PrivateIpAddress"] = actor["private_ip"]
        state_name = state.get("Name") if isinstance(state, Mapping) else None
        if (
            any(instance.get(name) != value for name, value in expected_values.items())
            or not isinstance(placement, Mapping)
            or placement.get("AvailabilityZone") != actor["availability_zone"]
            or not isinstance(state_name, str)
            or state_name in {"shutting-down", "terminated"}
        ):
            raise MutationDenied("EC2 actor cloud identity differs from immutable authority")
        tag_values = instance.get("Tags")
        if not isinstance(tag_values, list):
            raise MutationDenied("EC2 actor validation omitted ownership tags")
        tags: dict[str, str] = {}
        for tag in tag_values:
            if (
                not isinstance(tag, Mapping)
                or not isinstance(tag.get("Key"), str)
                or not isinstance(tag.get("Value"), str)
                or tag["Key"] in tags
            ):
                raise MutationDenied("EC2 actor validation returned malformed ownership tags")
            tags[str(tag["Key"])] = str(tag["Value"])
        if any(
            tags.get(name) != value
            for name, value in cast(Mapping[str, str], actor["expected_tags"]).items()
        ):
            raise MutationDenied("EC2 actor ownership tags differ from immutable authority")
        return actor, state_name

    def _record_instance_actor(
        self, actor: Mapping[str, Any], operation: str
    ) -> None:
        identity = {
            name: actor[name]
            for name in (
                "actor_type",
                "actor_id",
                "instance_id",
                "region",
                "vpc_id",
                "subnet_id",
                "availability_zone",
                "private_ip",
            )
        }
        self.ledger.actor(
            operation=operation,
            actor_type=str(actor["actor_type"]),
            actor_id=str(actor["actor_id"]),
            instance_id=str(actor["instance_id"]),
            region=str(actor["region"]),
            identity_sha256=canonical_sha256(identity),
        )

    def _validate_instance_actor(
        self, instance_id: str, region: str, operation: str
    ) -> dict[str, Any]:
        actor, _state = self._describe_instance_actor(instance_id, region)
        self._record_instance_actor(actor, operation)
        return actor

    def deploy_controller(self, mode: str, *, cleanup: bool = False) -> Mapping[str, Any]:
        if mode not in {"read-only", "active"} or self.controller_variables is None:
            raise ContractError("controller deployment mode or preparation is invalid")
        variables = copy.deepcopy(self.controller_variables)
        variables["deployment_mode"] = mode
        if mode == "active":
            self.active_deployment_attempted = True
        output = self.controller_workspace.apply(variables, mode, cleanup=cleanup)
        ownership = _mapping(_output_value(output, "dynamic_route_ownership"), "dynamic route ownership")
        iam = _mapping(_output_value(output, "controller_iam"), "controller IAM output")
        lifecycle = _mapping(
            _output_value(output, "protected_acceptance_lifecycle"),
            "protected acceptance lifecycle output",
        )
        if (
            ownership.get("deployment_mode") != mode
            or ownership.get("terraform_manages_target") is not False
            or iam.get("deployment_mode") != mode
            or lifecycle
            != {
                "enabled": True,
                "dynamodb_deletion_protection": False,
                "observer_final_snapshots": False,
                "customer_managed_storage_key": False,
            }
        ):
            raise ContractError("controller Terraform output differs from protected lifecycle mode")
        exact_arns = iam.get("exact_route_table_arns")
        if not isinstance(exact_arns, list):
            raise ContractError("controller IAM output omitted exact route tables")
        expected = sorted(
            contract["route_table_arn"]
            for contract in cast(Mapping[str, Mapping[str, Any]], variables["managed_route_tables"]).values()
        )
        if sorted(exact_arns) != (expected if mode == "active" else []):
            raise ContractError("controller mode has incorrect exact route-table IAM scope")
        self.controller_output = output
        self.controller_variables = variables
        self.controller_mode = mode
        return {
            "mode": mode,
            "exact_route_table_arns": sorted(exact_arns),
            "actors": self._actor_summary(output),
        }

    def _dynamo_item(self, partition: str, sort_key: str) -> dict[str, Any] | None:
        assert self.topology is not None
        response = self.aws.json(
            [
                "dynamodb",
                "get-item",
                "--table-name",
                cast(Mapping[str, str], self.topology["dynamodb"])["table"],
                "--consistent-read",
                "--key",
                json.dumps(
                    {"pk": {"S": partition}, "sk": {"S": sort_key}},
                    separators=(",", ":"),
                ),
            ],
            region=self.config.controller.region,
        )
        item = response.get("Item")
        if item is None:
            return None
        item = _mapping(item, "DynamoDB item")
        payload_value = _mapping(item.get("payload"), "DynamoDB payload attribute").get("S")
        return _mapping(strict_json_loads(_string(payload_value, "DynamoDB payload"), "DynamoDB payload"), "DynamoDB payload")

    def _owner_router(self, stable_node_id: Any) -> str | None:
        if not isinstance(stable_node_id, str) or not stable_node_id:
            return None
        matches = [
            router_id
            for router_id, identity in self.router_nodes.items()
            if identity["stable_node_id"] == stable_node_id
        ]
        if len(matches) != 1:
            return None
        return matches[0]

    @staticmethod
    def _prometheus_labels(text: str, metric: str) -> list[tuple[dict[str, str], float]]:
        rows: list[tuple[dict[str, str], float]] = []
        pattern = re.compile(
            rf"^{re.escape(metric)}(?:\{{(?P<labels>[^}}]*)\}})?\s+(?P<value>-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)$"
        )
        for line in text.splitlines():
            match = pattern.fullmatch(line.strip())
            if match is None:
                continue
            labels: dict[str, str] = {}
            raw_labels = match.group("labels") or ""
            if raw_labels:
                for label_match in re.finditer(r'(\w+)="((?:[^"\\]|\\.)*)"(?:,|$)', raw_labels):
                    labels[label_match.group(1)] = bytes(
                        label_match.group(2), "utf-8"
                    ).decode("unicode_escape")
            rows.append((labels, float(match.group("value"))))
        return rows

    def _active_metric_label(self, metrics: str, metric: str, domain_id: str, label: str) -> str:
        values = [
            labels.get(label, "")
            for labels, value in self._prometheus_labels(metrics, metric)
            if labels.get("domain") == domain_id and value == 1.0
        ]
        return values[0] if len(values) == 1 else "unknown"

    @staticmethod
    def _http_get(url: str) -> tuple[int, str]:
        request = urllib.request.Request(url, method="GET", headers={"Accept": "text/plain"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                body = response.read(4 * 1024 * 1024 + 1)
                if len(body) > 4 * 1024 * 1024:
                    raise ContractError("controller endpoint response exceeded its bound")
                return response.status, body.decode("utf-8")
        except urllib.error.HTTPError as error:
            return error.code, error.read(4096).decode("utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            return 0, "unavailable"

    def _controller_endpoint_snapshots(self) -> dict[str, dict[str, Any]]:
        assert self.controller_output is not None
        actors = {
            str(actor["actor_id"]): actor
            for actor in self._controller_actors(self.controller_output)
        }
        result: dict[str, dict[str, Any]] = {}
        for controller_id in self.config.controller.controller_ids:
            actor = actors[controller_id]
            address = str(actor["private_ip"])
            base = f"http://{address}:{self.config.controller.metrics_port}"
            health_status, _health = self._http_get(base + "/healthz")
            ready_status, ready = self._http_get(base + "/readyz")
            metrics_status, metrics = self._http_get(base + "/metrics")
            if metrics_status != 200:
                metrics = "unavailable"
            ready_reason = sanitize_text(
                ready, self.protected_secrets, maximum=128
            )
            if ready_reason not in READINESS_REASONS:
                ready_reason = "unavailable"
            result[controller_id] = {
                "instance_id": actor["instance_id"],
                "private_ip": address,
                "health_status": health_status,
                "ready_status": ready_status,
                "ready_reason": ready_reason,
                "metrics": metrics,
                "metrics_sha256": hashlib.sha256(metrics.encode("utf-8")).hexdigest(),
            }
        return result

    def _tailnet_consensus(self, domain_id: str) -> dict[str, Any]:
        assert self.topology_identity is not None and self.deployment is not None
        topology_hash = str(self.topology_identity["canonical_sha256"])
        contributors: list[dict[str, Any]] = []
        domain = self.deployment.seed.domains_by_id[domain_id]
        expected_prefixes = self.deployment.seed.sites[str(domain["site_id"])]["local_prefixes"]
        for controller_id in self.config.controller.controller_ids:
            payload = self._dynamo_item(
                f"observations#{self.config.run_id}#{topology_hash}#{controller_id}",
                f"controller#{controller_id}",
            )
            if payload is None:
                continue
            try:
                captured_at = parse_runtime_timestamp(
                    payload.get("captured_at"), "observation capture time"
                )
                expires_at = parse_runtime_timestamp(
                    payload.get("expires_at"), "observation expiry time"
                )
            except ContractError:
                continue
            now = self.wall_clock()
            if (
                payload.get("controller_id") != controller_id
                or payload.get("topology_hash") != topology_hash
                or isinstance(payload.get("sequence"), bool)
                or not isinstance(payload.get("sequence"), int)
                or payload.get("sequence", 0) < 1
                or payload.get("backend_healthy") is not True
                or captured_at > now + dt.timedelta(seconds=5)
                or now - captured_at
                > dt.timedelta(
                    seconds=self.config.controller.policy_seconds[
                        "observation_freshness"
                    ]
                )
                or expires_at <= now
            ):
                continue
            domains = payload.get("domains")
            observation = domains.get(domain_id) if isinstance(domains, Mapping) else None
            if not isinstance(observation, Mapping):
                continue
            stable_id = observation.get("stable_node_id")
            sole_owner = (
                observation.get("sole_primary") is True
                and isinstance(stable_id, str)
                and bool(stable_id)
            )
            try:
                prefix_healthy = (
                    sorted(observation.get("advertised_prefixes", [])) == expected_prefixes
                    and sorted(observation.get("enabled_prefixes", [])) == expected_prefixes
                )
            except TypeError:
                prefix_healthy = False
            owner_healthy = bool(
                sole_owner
                and observation.get("online") is True
                and observation.get("expired") is False
                and observation.get("healthy") is True
                and prefix_healthy
            )
            owner_since_value = observation.get("owner_since")
            owner_since: str | None = None
            if owner_since_value is not None:
                try:
                    parsed_owner_since = parse_runtime_timestamp(
                        owner_since_value, "observation owner_since"
                    )
                except ContractError:
                    owner_healthy = False
                else:
                    if parsed_owner_since > captured_at:
                        owner_healthy = False
                    else:
                        owner_since = evidence_runtime_timestamp(
                            owner_since_value, "observation owner_since"
                        )
            contributors.append(
                {
                    "controller_id": controller_id,
                    "sequence": payload["sequence"],
                    "captured_at": evidence_runtime_timestamp(
                        payload["captured_at"], "observation capture time"
                    ),
                    "expires_at": evidence_runtime_timestamp(
                        payload["expires_at"], "observation expiry time"
                    ),
                    "fresh": True,
                    "backend_healthy": True,
                    "sole_primary": sole_owner,
                    "owner_healthy": owner_healthy,
                    "owner_node_sha256": hash_identity(str(stable_id)) if sole_owner else None,
                    "owner_since": owner_since,
                }
            )
        required = self.config.controller.policy["observation_quorum"]
        owner_hashes = {
            contributor["owner_node_sha256"]
            for contributor in contributors
            if contributor["owner_node_sha256"] is not None
        }
        unanimous = (
            len(contributors) >= required
            and len(owner_hashes) == 1
            and all(contributor["sole_primary"] for contributor in contributors)
        )
        owner_hash = next(iter(owner_hashes)) if unanimous else None
        healthy = [
            contributor
            for contributor in contributors
            if unanimous
            and contributor["owner_healthy"]
            and contributor["owner_node_sha256"] == owner_hash
        ]
        stable_ids = [
            identity["stable_node_id"]
            for identity in self.router_nodes.values()
            if hash_identity(str(identity["stable_node_id"])) == owner_hash
        ]
        owner_router = self._owner_router(stable_ids[0]) if len(stable_ids) == 1 else None
        agreement = owner_router is not None and len(healthy) >= required
        return {
            "owner_router_id": owner_router if agreement else None,
            "owner_node_sha256": owner_hash if agreement else None,
            "observer_quorum": len(healthy) if agreement else 0,
            "agreement": agreement,
            "contributors": contributors,
        }

    @staticmethod
    def _optional_evidence_timestamp(value: Any, label: str) -> str | None:
        if value is None:
            return None
        return evidence_runtime_timestamp(value, label)

    def _durable_evidence(
        self,
        payload: Mapping[str, Any] | None,
        domain: Mapping[str, Any],
        router_by_eni: Mapping[str, str],
    ) -> dict[str, Any]:
        if payload is None:
            return {
                "present": False,
                "phase": None,
                "stable_owner": None,
                "observed_owner": None,
                "lease_holder": None,
                "fence_term": 0,
                "revision": 0,
                "cooldown_until": None,
                "lease_record_version": 0,
                "lease_renewed_at": None,
                "lease_expires_at": None,
                "owner_observed_at": None,
                "last_transition_at": None,
                "error_code": None,
                "error_ambiguous": False,
                "transaction": None,
            }

        assert self.deployment is not None and self.topology_identity is not None
        site_id = str(domain["site_id"])
        site = self.deployment.seed.sites[site_id]
        raw_authority = _mapping(payload.get("authority"), "durable domain authority")
        expected_authority = {
            "topology_hash": self.topology_identity["canonical_sha256"],
            "deployment_id": self.config.run_id,
            "domain_id": domain["id"],
            "site_id": site_id,
            "vpc_id": site["vpc_id"],
            "region": site["region"],
            "source_prefix": domain["source_prefix"],
            "route_table_id": domain["route_table_id"],
            "gwlbe_subnet_id": domain["gwlbe_subnet_id"],
            "route_table_association_id": domain["route_table_association_id"],
            "remote_prefixes": list(domain["remote_prefixes"]),
            "preferred_owner": self.router_nodes[str(domain["preferred_owner"])][
                "stable_node_id"
            ],
            "owners": [
                {
                    "router_id": router["id"],
                    "stable_node_id": self.router_nodes[str(router["id"])]["stable_node_id"],
                    "instance_id": router["instance_id"],
                    "eni_id": router["eni_id"],
                    "vpc_id": router["vpc_id"],
                    "subnet_id": router["subnet_id"],
                    "availability_zone": router["availability_zone"],
                    "region": router["region"],
                }
                for router in self.deployment.seed.routers
                if router["site_id"] == site_id
            ],
        }
        if raw_authority != expected_authority:
            raise ContractError("durable domain authority differs from the canonical topology")

        lease_value = payload.get("lease")
        lease = _mapping(lease_value, "durable lease") if lease_value is not None else None
        error_value = payload.get("error")
        state_error = (
            _mapping(error_value, "durable state error") if error_value is not None else None
        )
        transaction_value = payload.get("intent")
        transaction: dict[str, Any] | None = None
        if transaction_value is not None:
            intent = _mapping(transaction_value, "durable route intent")
            before = _mapping(intent.get("before"), "durable before snapshot")
            before_routes_value = before.get("routes")
            if not isinstance(before_routes_value, list):
                raise ContractError("durable before snapshot omitted routes")
            before_routes: list[dict[str, Any]] = []
            for raw_route in before_routes_value:
                route = _mapping(raw_route, "durable before route")
                eni_id = _string(route.get("target_eni_id"), "durable before ENI", pattern=_ENI_RE)
                before_routes.append(
                    {
                        "destination_prefix": _validate_prefix(
                            route.get("destination_prefix"), "durable before destination"
                        ),
                        "target_router_id": router_by_eni.get(eni_id),
                        "target_eni_id": eni_id,
                        "state": route.get("state"),
                        "origin": route.get("origin"),
                    }
                )
            before_routes.sort(key=lambda item: item["destination_prefix"])
            before_table = {
                "route_table_id": domain["route_table_id"],
                "vpc_id": site["vpc_id"],
                "gwlbe_subnet_id": domain["gwlbe_subnet_id"],
                "route_table_association_id": domain["route_table_association_id"],
                "explicit_association_count": 1,
                "association_state": "associated",
            }
            progress_value = intent.get("progress")
            if not isinstance(progress_value, list):
                raise ContractError("durable route intent omitted ordered progress")
            progress = []
            for raw_progress in progress_value:
                item = _mapping(raw_progress, "durable route progress")
                progress.append(
                    {
                        "destination_prefix": _validate_prefix(
                            item.get("destination_prefix"), "durable progress destination"
                        ),
                        "attempted": item.get("attempted_at") is not None,
                        "completed": item.get("completed_at") is not None,
                        "observed_eni_id": _optional_string(
                            item.get("observed_eni_id"),
                            "durable progress observed ENI",
                            pattern=_ENI_RE,
                        ),
                        "ambiguous": item.get("ambiguous") is True,
                    }
                )
            desired_owner = self._owner_router(intent.get("desired_owner"))
            if desired_owner is None:
                raise ContractError("durable route intent names an unknown desired owner")
            transaction = {
                "transaction_id_sha256": hash_identity(
                    _string(intent.get("transaction_id"), "durable transaction ID")
                ),
                "fence_term": _integer(intent.get("fence_term"), "durable transaction fence", 1),
                "desired_owner": desired_owner,
                "desired_eni_id": _string(
                    intent.get("desired_eni_id"), "durable desired ENI", pattern=_ENI_RE
                ),
                "before_sha256": route_snapshot_sha256(before_table, before_routes),
                "progress": progress,
            }
        return {
            "present": True,
            "phase": payload.get("phase"),
            "stable_owner": self._owner_router(payload.get("stable_owner")),
            "observed_owner": self._owner_router(payload.get("observed_owner")),
            "lease_holder": lease.get("holder_id") if lease is not None else None,
            "fence_term": _integer(payload.get("fence_term"), "durable fence term"),
            "revision": _integer(payload.get("revision"), "durable revision"),
            "cooldown_until": self._optional_evidence_timestamp(
                payload.get("cooldown_until"), "durable cooldown"
            ),
            "lease_record_version": (
                _integer(lease.get("record_version"), "durable lease record version", 1)
                if lease is not None
                else 0
            ),
            "lease_renewed_at": (
                self._optional_evidence_timestamp(lease.get("renewed_at"), "durable lease renewal")
                if lease is not None
                else None
            ),
            "lease_expires_at": (
                self._optional_evidence_timestamp(lease.get("expires_at"), "durable lease expiry")
                if lease is not None
                else None
            ),
            "owner_observed_at": self._optional_evidence_timestamp(
                payload.get("owner_observed_at"), "durable owner observed"
            ),
            "last_transition_at": self._optional_evidence_timestamp(
                payload.get("last_transition_at"), "durable last transition"
            ),
            "error_code": state_error.get("code") if state_error is not None else None,
            "error_ambiguous": state_error.get("ambiguous") is True if state_error else False,
            "transaction": transaction,
        }

    def _read_route_table_once(
        self, domain: Mapping[str, Any], router_by_eni: Mapping[str, str]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        assert self.deployment is not None
        site = self.deployment.seed.sites[str(domain["site_id"])]
        route_response = self.aws.json(
            ["ec2", "describe-route-tables", "--route-table-ids", str(domain["route_table_id"])],
            region=str(site["region"]),
        )
        tables = route_response.get("RouteTables")
        if not isinstance(tables, list) or len(tables) != 1:
            raise ContractError("AWS route observation did not return one exact route table")
        table = _mapping(tables[0], "AWS route table")
        if table.get("RouteTableId") != domain["route_table_id"] or table.get("VpcId") != site["vpc_id"]:
            raise ContractError("AWS route table identity differs from exact domain authority")
        associations = table.get("Associations")
        if not isinstance(associations, list):
            raise ContractError("AWS route observation omitted route-table associations")
        if any(
            isinstance(association, Mapping) and association.get("Main") is True
            for association in associations
        ):
            raise ContractError("configured GWLBE route table unexpectedly has a main association")
        explicit = [
            association
            for association in associations
            if isinstance(association, Mapping)
            and association.get("Main") is False
            and isinstance(association.get("AssociationState"), Mapping)
            and association["AssociationState"].get("State") == "associated"
        ]
        if len(explicit) != 1:
            raise ContractError("AWS route table does not have one active explicit association")
        association = explicit[0]
        if (
            association.get("RouteTableAssociationId")
            != domain["route_table_association_id"]
            or association.get("RouteTableId") != domain["route_table_id"]
            or association.get("SubnetId") != domain["gwlbe_subnet_id"]
        ):
            raise ContractError("AWS route-table association differs from immutable authority")
        route_values = table.get("Routes")
        if not isinstance(route_values, list):
            raise ContractError("AWS route observation omitted routes")
        routes: list[dict[str, Any]] = []
        for prefix in domain["remote_prefixes"]:
            matches = [
                route
                for route in route_values
                if isinstance(route, Mapping) and route.get("DestinationCidrBlock") == prefix
            ]
            if len(matches) != 1:
                raise ContractError("AWS route observation omitted one exact managed prefix")
            route = matches[0]
            eni_id = _string(route.get("NetworkInterfaceId"), "observed route ENI", pattern=_ENI_RE)
            routes.append(
                {
                    "destination_prefix": prefix,
                    "target_router_id": router_by_eni.get(eni_id),
                    "target_eni_id": eni_id,
                    "state": route.get("State"),
                    "origin": route.get("Origin"),
                }
            )
        metadata = {
            "route_table_id": domain["route_table_id"],
            "vpc_id": site["vpc_id"],
            "gwlbe_subnet_id": domain["gwlbe_subnet_id"],
            "route_table_association_id": domain["route_table_association_id"],
            "explicit_association_count": len(explicit),
            "association_state": "associated",
        }
        return metadata, routes

    def _observe_route_table(
        self, domain: Mapping[str, Any], router_by_eni: Mapping[str, str]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        first_table, first_routes = self._read_route_table_once(domain, router_by_eni)
        self.sleep(min(1.0, self.config.controller.policy_seconds["observation_interval"]))
        second_table, second_routes = self._read_route_table_once(domain, router_by_eni)
        if first_table != second_table or first_routes != second_routes:
            raise ContractError("authoritative route readback was not stable across repeated reads")
        route_table = {
            **second_table,
            "stable_read_count": 2,
            "snapshot_sha256": route_snapshot_sha256(second_table, second_routes),
        }
        return route_table, second_routes

    def _observe_all(self, stage: str) -> list[dict[str, Any]]:
        if self.deployment is None or self.topology_identity is None:
            raise ContractError("controller observation requires prepared topology")
        endpoint_snapshots = self._controller_endpoint_snapshots()
        self.ledger.tailnet("tailscale:ListDevices")
        devices = self.tailnet.list_devices()
        online_by_router: dict[str, bool] = {}
        for router_id, identity in self.router_nodes.items():
            matches = [device for device in devices if device.get("id") == identity["device_id"]]
            online_by_router[router_id] = len(matches) == 1 and matches[0].get("online") is True
        observations: list[dict[str, Any]] = []
        router_by_eni = {
            str(router["eni_id"]): str(router["id"])
            for router in self.deployment.seed.routers
        }
        for domain in self.deployment.seed.domains:
            domain_id = str(domain["id"])
            payload = self._dynamo_item(
                f"deployment#{self.config.run_id}", f"domain#{domain_id}"
            )
            durable = self._durable_evidence(payload, domain, router_by_eni)
            tailnet = self._tailnet_consensus(domain_id)
            route_table, routes = self._observe_route_table(domain, router_by_eni)
            target_owners = {route["target_router_id"] for route in routes}
            route_owner = next(iter(target_owners)) if len(target_owners) == 1 else None
            endpoints: list[dict[str, Any]] = []
            for controller_id in self.config.controller.controller_ids:
                endpoint = endpoint_snapshots[controller_id]
                metrics = endpoint["metrics"]
                fence_rows = [
                    value
                    for labels, value in self._prometheus_labels(
                        metrics, "envelope_controller_lease_fence_term"
                    )
                    if labels.get("domain") == domain_id
                ]
                mode = self._active_metric_label(
                    metrics,
                    "envelope_controller_domain_mode",
                    domain_id,
                    "mode",
                )
                role = self._active_metric_label(
                    metrics,
                    "envelope_controller_domain_role",
                    domain_id,
                    "role",
                )
                phase = self._active_metric_label(
                    metrics,
                    "envelope_controller_domain_phase",
                    domain_id,
                    "phase",
                )
                endpoints.append(
                    {
                        "controller_id": controller_id,
                        "instance_id": endpoint["instance_id"],
                        "private_ip": endpoint["private_ip"],
                        "health_status": endpoint["health_status"],
                        "ready_status": endpoint["ready_status"],
                        "ready_reason": endpoint["ready_reason"],
                        "mode": mode
                        if mode in {"active", "read-only", "unknown"}
                        else "unknown",
                        "role": role
                        if role in {"leader", "follower", "read-only", "unknown"}
                        else "unknown",
                        "phase": phase if phase in PHASES else "unknown",
                        "fence_term": int(fence_rows[0]) if len(fence_rows) == 1 else 0,
                        "metrics_sha256": endpoint["metrics_sha256"],
                    }
                )
            tailnet_owner = tailnet["owner_router_id"]
            agreement_owner = durable["stable_owner"] if durable["present"] else tailnet_owner
            observations.append(
                {
                    "stage": stage,
                    "captured_at": utc_now(),
                    "domain_id": domain_id,
                    "preferred_owner": domain["preferred_owner"],
                    "dynamodb": durable,
                    "controller_endpoints": endpoints,
                    "tailnet": {
                        **tailnet,
                        "failed_router_online": (
                            online_by_router.get(self.failed_router_id)
                            if self.failed_router_id is not None
                            else None
                        ),
                    },
                    "aws_route_table": route_table,
                    "aws_routes": routes,
                    "route_agreement": route_owner is not None
                    and route_owner == agreement_owner
                    and tailnet_owner == agreement_owner,
                }
            )
        return observations

    def _observation_matches(
        self, stage: str, values: Sequence[Mapping[str, Any]], context: Mapping[str, Any]
    ) -> bool:
        if self.deployment is None or len(values) != len(self.deployment.seed.domains):
            return False
        selected = next(
            (value for value in values if value["domain_id"] == context.get("domain_id")),
            None,
        )
        if stage == "read-only-cold":
            return all(
                not value["dynamodb"]["present"]
                and value["route_agreement"]
                and value["tailnet"]["observer_quorum"] >= 2
                and all(
                    endpoint["health_status"] == 200
                    and endpoint["ready_status"] == 503
                    and endpoint["ready_reason"] == "domain-not-initialized"
                    and endpoint["mode"] == "read-only"
                    and endpoint["role"] == "read-only"
                    for endpoint in value["controller_endpoints"]
                )
                for value in values
            )
        if stage == "active-baseline":
            return all(
                value["dynamodb"]["present"]
                and value["dynamodb"]["phase"] == "stable"
                and value["route_agreement"]
                and value["tailnet"]["observer_quorum"] >= 2
                and sum(endpoint["ready_status"] == 200 for endpoint in value["controller_endpoints"])
                >= 2
                and all(
                    endpoint["mode"] in {"active", "unknown"}
                    for endpoint in value["controller_endpoints"]
                )
                for value in values
            )
        if stage == "lease-renewal":
            baseline_values = context.get("baseline")
            if not isinstance(baseline_values, Sequence):
                return False
            before = next(
                (
                    value
                    for value in baseline_values
                    if isinstance(value, Mapping)
                    and value.get("domain_id") == context.get("domain_id")
                ),
                None,
            )
            if selected is None or before is None:
                return False
            before_durable = before["dynamodb"]
            durable = selected["dynamodb"]
            try:
                elapsed = (
                    parse_timestamp(selected["captured_at"], "renewal capture")
                    - parse_timestamp(before["captured_at"], "baseline capture")
                ).total_seconds()
            except ContractError:
                return False
            return (
                durable["lease_holder"] == before_durable["lease_holder"]
                and durable["lease_holder"] is not None
                and durable["fence_term"] == before_durable["fence_term"]
                and durable["lease_record_version"]
                > before_durable["lease_record_version"]
                and elapsed >= self.config.controller.policy_seconds["lease_renew_interval"]
                and selected["route_agreement"]
            )
        if selected is None:
            return False
        alternate = context.get("alternate_router_id")
        preferred = selected["preferred_owner"]
        if stage == "observer-disagreement":
            baseline_values = context.get("baseline")
            if not isinstance(baseline_values, Sequence):
                return False
            before = next(
                (
                    value
                    for value in baseline_values
                    if isinstance(value, Mapping)
                    and value.get("domain_id") == selected["domain_id"]
                ),
                None,
            )
            return bool(
                before is not None
                and selected["tailnet"]["agreement"] is False
                and selected["dynamodb"]["phase"] == "degraded"
                and selected["dynamodb"]["error_code"] == "observation-quorum"
                and selected["dynamodb"]["stable_owner"] == preferred
                and selected["aws_route_table"]["snapshot_sha256"]
                == before["aws_route_table"]["snapshot_sha256"]
                and selected["route_agreement"] is False
            )
        if stage == "route-progress":
            transaction = selected["dynamodb"]["transaction"]
            return bool(
                selected["tailnet"]["owner_router_id"] == alternate
                and selected["dynamodb"]["phase"]
                in {"route-intent-persisted", "routes-converging"}
                and isinstance(transaction, Mapping)
                and transaction.get("desired_owner") == alternate
                and not all(
                    item.get("completed") is True
                    for item in transaction.get("progress", [])
                )
            )
        if stage == "router-failover":
            return (
                selected["tailnet"]["owner_router_id"] == alternate
                and selected["tailnet"]["failed_router_online"] is False
                and selected["dynamodb"]["phase"] == "stable"
                and selected["dynamodb"]["stable_owner"] == alternate
                and selected["route_agreement"]
            )
        if stage == "leader-handoff":
            fault = cast(Mapping[str, Any], context.get("leader_fault", {}))
            return (
                selected["dynamodb"]["lease_holder"] not in {None, fault.get("previous_controller_id")}
                and selected["dynamodb"]["fence_term"] > int(fault.get("previous_fence", 0))
                and selected["dynamodb"]["stable_owner"] == alternate
                and selected["route_agreement"]
            )
        if stage == "durable-alternate":
            return (
                selected["dynamodb"]["phase"] == "stable"
                and selected["dynamodb"]["stable_owner"] == alternate
                and selected["route_agreement"]
            )
        if stage == "failback-gate":
            return (
                selected["tailnet"]["owner_router_id"] == preferred
                and selected["dynamodb"]["phase"] == "owner-observed"
                and selected["dynamodb"]["stable_owner"] == alternate
                and all(route["target_router_id"] == alternate for route in selected["aws_routes"])
            )
        if stage == "failback-stable":
            gate_values = context.get("gate")
            gate = (
                next(
                    (
                        value
                        for value in gate_values
                        if isinstance(value, Mapping)
                        and value.get("domain_id") == selected["domain_id"]
                    ),
                    None,
                )
                if isinstance(gate_values, Sequence)
                else None
            )
            owner_observed_at = (
                gate["dynamodb"]["owner_observed_at"] if gate is not None else None
            )
            cooldown_until = gate["dynamodb"]["cooldown_until"] if gate is not None else None
            if owner_observed_at is None or cooldown_until is None:
                return False
            captured = parse_timestamp(selected["captured_at"], "failback capture")
            return (
                selected["tailnet"]["owner_router_id"] == preferred
                and selected["dynamodb"]["phase"] == "stable"
                and selected["dynamodb"]["stable_owner"] == preferred
                and selected["route_agreement"]
                and captured
                >= parse_timestamp(cooldown_until, "failback cooldown")
                and (
                    captured
                    - parse_timestamp(owner_observed_at, "failback owner observed")
                ).total_seconds()
                >= self.config.controller.policy_seconds["failback_stability"]
            )
        return False

    def wait_observation(
        self, stage: str, context: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        if stage not in STAGES:
            raise ContractError("unsupported controller observation stage")
        timeout = (
            self.config.controller.timeouts["readiness_seconds"]
            if stage in {"read-only-cold", "active-baseline"}
            else self.config.controller.timeouts["transition_seconds"]
        )
        deadline = self.monotonic() + timeout
        last: list[dict[str, Any]] = []
        while self.monotonic() < deadline:
            last = self._observe_all(stage)
            if self._observation_matches(stage, last, context):
                return last
            self.sleep(min(2.0, max(0.0, deadline - self.monotonic())))
        raise ContractError(f"controller observation did not converge at {stage}")

    def select_domain(self, observations: Sequence[Mapping[str, Any]]) -> Mapping[str, str]:
        if self.deployment is None:
            raise ContractError("cannot select a failover domain before appliance deployment")
        routers = self.deployment.seed.routers_by_id
        for observation in sorted(observations, key=lambda item: str(item["domain_id"])):
            preferred = str(observation["preferred_owner"])
            if (
                observation["dynamodb"]["stable_owner"] == preferred
                and observation["tailnet"]["owner_router_id"] == preferred
                and observation["route_agreement"] is True
            ):
                site_id = str(routers[preferred]["site_id"])
                alternates = sorted(
                    router_id
                    for router_id, router in routers.items()
                    if router["site_id"] == site_id and router_id != preferred
                )
                if len(alternates) == 1:
                    return {
                        "domain_id": str(observation["domain_id"]),
                        "router_id": preferred,
                        "alternate_router_id": alternates[0],
                    }
        raise ContractError("no stable domain has its preferred native owner for a failback exercise")

    def _workload_pair(self, selection: Mapping[str, str]) -> tuple[str, dict[str, str], str, dict[str, str]]:
        assert self.deployment is not None
        domain = self.deployment.seed.domains_by_id[selection["domain_id"]]
        source_site = str(domain["site_id"])
        source_matches = [
            (role, workload)
            for role, workload in self.deployment.workloads[source_site].items()
            if workload["cidr"] == domain["source_prefix"]
        ]
        destination_site = next(site for site in sorted(self.deployment.workloads) if site != source_site)
        destination_matches = [
            (role, workload)
            for role, workload in self.deployment.workloads[destination_site].items()
            if workload["cidr"] in domain["remote_prefixes"]
        ]
        if len(source_matches) != 1 or not destination_matches:
            raise ContractError("selected domain does not map to exact workload probe endpoints")
        source_role, source = source_matches[0]
        destination_role, destination = sorted(destination_matches)[0]
        return (
            f"{source_site}-{source_role}",
            source,
            f"{destination_site}-{destination_role}",
            destination,
        )

    def _send_workload_command(
        self, instance_id: str, region: str, command: str, *, timeout_seconds: int
    ) -> str:
        assert self.deployment is not None
        actor = self._validate_instance_actor(
            instance_id, region, "ssm:SendCommand"
        )
        if actor["actor_type"] != "workload":
            self.ledger.remote(str(actor["actor_type"]))
        self.ledger.remote("workload")
        response = self.aws.json(
            [
                "ssm",
                "send-command",
                "--document-name",
                "AWS-RunShellScript",
                "--instance-ids",
                instance_id,
                "--timeout-seconds",
                str(timeout_seconds),
                "--parameters",
                json.dumps(
                    {
                        "commands": [command],
                        "executionTimeout": [str(timeout_seconds)],
                    },
                    separators=(",", ":"),
                ),
                "--comment",
                f"Envelope controller acceptance {self.config.run_id}",
            ],
            region=region,
        )
        command_id = response.get("Command", {}).get("CommandId")
        return _string(command_id, "SSM command ID", pattern=re.compile(r"[0-9a-f-]{36}"))

    def _wait_command(
        self, command_id: str, instance_id: str, region: str, *, timeout_seconds: int
    ) -> dict[str, Any]:
        deadline = self.monotonic() + timeout_seconds
        while self.monotonic() < deadline:
            try:
                response = self.aws.json(
                    [
                        "ssm",
                        "get-command-invocation",
                        "--command-id",
                        command_id,
                        "--instance-id",
                        instance_id,
                    ],
                    region=region,
                )
            except (HardTimeout, CleanupTimeout, TerminationRequested):
                raise
            except RuntimeError as error:
                if "InvocationDoesNotExist" in str(error):
                    self.sleep(1)
                    continue
                raise
            status = response.get("Status")
            if status in SSM_TERMINAL_STATUSES:
                return response
            self.sleep(1)
        return {"Status": "InProgress", "StandardOutputContent": "", "StandardErrorContent": ""}

    def _send_established_command(
        self, instance_id: str, region: str, command: str, *, timeout_seconds: int
    ) -> str:
        command_id = self._send_workload_command(
            instance_id, region, command, timeout_seconds=timeout_seconds
        )
        if command_id in self.established_commands:
            raise ContractError("SSM returned a duplicate established command ID")
        self.established_commands[command_id] = (instance_id, region)
        return command_id

    def _wait_established_command(
        self, command_id: str, instance_id: str, region: str, *, timeout_seconds: int
    ) -> dict[str, Any]:
        if self.established_commands.get(command_id) != (instance_id, region):
            raise ContractError("established command tracking identity differs from its handle")
        result = self._wait_command(
            command_id, instance_id, region, timeout_seconds=timeout_seconds
        )
        if result.get("Status") in SSM_TERMINAL_STATUSES:
            self.established_commands.pop(command_id, None)
        return result

    def _cancel_established_command(
        self, command_id: str, instance_id: str, region: str, *, timeout_seconds: int
    ) -> dict[str, Any]:
        if self.established_commands.get(command_id) != (instance_id, region):
            raise ContractError("established command cancellation identity is untracked")
        self.aws.json(
            [
                "ssm",
                "cancel-command",
                "--command-id",
                command_id,
                "--instance-ids",
                instance_id,
            ],
            region=region,
        )
        result = self._wait_established_command(
            command_id,
            instance_id,
            region,
            timeout_seconds=timeout_seconds,
        )
        if result.get("Status") not in SSM_TERMINAL_STATUSES:
            raise ContractError("cancelled established command did not reach a terminal status")
        return result

    def start_established_flows(self, selection: Mapping[str, str]) -> Mapping[str, Any]:
        assert self.deployment is not None
        source_name, source, destination_name, destination = self._workload_pair(selection)
        source_site = source_name.split("-", 1)[0]
        region = str(self.deployment.seed.sites[source_site]["region"])
        duration = established_stream_duration_seconds(self.config)
        count = min(ESTABLISHED_MAX_MARKERS, max(100, duration * 4))
        interval = duration / (count + 1)
        commands: dict[str, dict[str, str]] = {}
        for offset, protocol in enumerate(("tcp", "udp")):
            flow_id = f"{self.config.run_id}-established-{protocol}"
            barrier_path = f"/run/envelope-e2e/{flow_id}.ack.json"
            agent_command = " ".join(
                shlex.quote(part)
                for part in (
                    "/opt/envelope/e2e-agent",
                    "stream",
                    "--protocol",
                    protocol,
                    "--host",
                    destination["private_ip"],
                    "--port",
                    "5201",
                    "--source-ip",
                    source["private_ip"],
                    "--source-port",
                    str(60000 + offset),
                    "--flow-id",
                    flow_id,
                    "--count",
                    str(count),
                    "--interval",
                    f"{interval:.6f}",
                    "--timeout",
                    str(duration),
                    "--structured-result",
                    "--ack-barrier-path",
                    barrier_path,
                )
            )
            command = (
                "set -eu; install -d -m 0700 /run/envelope-e2e; rm -f -- "
                f"{shlex.quote(barrier_path)}; exec {agent_command}"
            )
            command_id = self._send_established_command(
                source["instance_id"], region, command, timeout_seconds=duration + 30
            )
            commands[protocol] = {
                "command_id": command_id,
                "instance_id": source["instance_id"],
                "region": region,
                "flow_id": flow_id,
                "source_ip": source["private_ip"],
                "source_port": str(60000 + offset),
                "expected_markers": str(count),
                "timeout_seconds": str(duration + 30),
                "barrier_path": barrier_path,
            }
        tcp_barrier = shlex.quote(commands["tcp"]["barrier_path"])
        udp_barrier = shlex.quote(commands["udp"]["barrier_path"])
        readiness_command = " ".join(
            (
                "set -eu;",
                "for attempt in $(seq 1 50); do",
                "tcp_count=$(ss -H -a -nt state established 'sport = :60000' | wc -l);",
                "udp_count=$(ss -H -a -un 'sport = :60001' | wc -l);",
                f"if [ -s {tcp_barrier} ] && [ -s {udp_barrier} ] &&",
                "[ \"$tcp_count\" -ge 1 ] && [ \"$udp_count\" -ge 1 ]; then",
                "sample_ns=$(python3 -c 'import time; print(time.monotonic_ns())');",
                "printf '{\"ready\":true,\"sampled_monotonic_ns\":%s,\"tcp_source_port\":60000,\"udp_source_port\":60001}\\n' \"$sample_ns\";",
                "exit 0; fi; sleep 0.2; done; exit 1",
            )
        )
        readiness_id = self._send_established_command(
            source["instance_id"], region, readiness_command, timeout_seconds=30
        )
        readiness = self._wait_established_command(
            readiness_id,
            source["instance_id"],
            region,
            timeout_seconds=40,
        )
        if readiness.get("Status") != "Success":
            raise ContractError("established TCP and UDP sockets were not sampled before fault")
        sample = _mapping(
            strict_json_loads(
                str(readiness.get("StandardOutputContent", "")).strip(),
                "established socket sample",
            ),
            "established socket sample",
        )
        _exact_keys(
            sample,
            {"ready", "sampled_monotonic_ns", "tcp_source_port", "udp_source_port"},
            "established socket sample",
        )
        sampled_monotonic_ns = _integer(
            sample["sampled_monotonic_ns"], "established sample monotonic time", 1
        )
        if (
            sample["ready"] is not True
            or sample["tcp_source_port"] != 60000
            or sample["udp_source_port"] != 60001
        ):
            raise ContractError("established socket sample differs from the fixed flow identities")
        return {
            "commands": commands,
            "sampled_at": utc_now(),
            "sampled_monotonic_ns": sampled_monotonic_ns,
            "source_workload": source_name,
            "destination_workload": destination_name,
            "source_instance_id": source["instance_id"],
            "destination_instance_id": destination["instance_id"],
        }

    def _instance_fault(
        self,
        action: str,
        instance_id: str,
        region: str,
        *,
        validated_actor: Mapping[str, Any] | None = None,
    ) -> None:
        operation = {"stop": "stop-instances", "start": "start-instances"}[action]
        iam_action = {"stop": "ec2:StopInstances", "start": "ec2:StartInstances"}[action]
        actor = (
            self._validate_instance_actor(instance_id, region, iam_action)
            if validated_actor is None
            else dict(validated_actor)
        )
        if (
            actor.get("instance_id") != instance_id
            or actor.get("region") != region
            or actor.get("actor_type") not in {"router", "controller"}
        ):
            raise MutationDenied("EC2 stop/start faults may target only routers or controllers")
        self.ledger.aws(iam_action)
        self.aws.json(["ec2", operation, "--instance-ids", instance_id], region=region)

    def _fault_restoration_phase(self, actor_type: str) -> str | None:
        if actor_type == "router":
            phase = self.router_restoration_phase
        elif actor_type == "controller":
            phase = self.controller_restoration_phase
        else:
            raise ContractError("EC2 fault restoration actor type is unsupported")
        if phase is not None and phase not in EC2_FAULT_RESTORATION_PHASES:
            raise ContractError("EC2 fault restoration phase is invalid")
        return phase

    def _set_fault_restoration_phase(self, actor_type: str, phase: str) -> None:
        if phase not in EC2_FAULT_RESTORATION_PHASES:
            raise ContractError("EC2 fault restoration phase is invalid")
        if actor_type == "router":
            self.router_restoration_phase = phase
        elif actor_type == "controller":
            self.controller_restoration_phase = phase
        else:
            raise ContractError("EC2 fault restoration actor type is unsupported")

    def _restore_instance_fault(
        self, instance_id: str, region: str, actor_type: str
    ) -> None:
        phase = self._fault_restoration_phase(actor_type)
        expected_instance = (
            self.failed_router_instance
            if actor_type == "router"
            else self.failed_controller_instance
        )
        if phase is None or expected_instance != instance_id:
            raise ContractError("EC2 fault restoration target is not armed")
        if phase == EC2_FAULT_RUNNING_PROVED:
            return
        deadline = self.monotonic() + EC2_FAULT_RESTORE_TIMEOUT_SECONDS
        start_attempted = False
        stable_running_reads = 0
        running_since: float | None = None
        last_start_error: RuntimeError | None = None
        last_observation_error: RuntimeError | None = None
        while True:
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                raise ContractError(
                    "EC2 fault restoration did not complete within its bounded window"
                )
            try:
                actor, state = self._describe_instance_actor(
                    instance_id,
                    region,
                    timeout_seconds=remaining,
                )
                last_observation_error = None
            except (HardTimeout, CleanupTimeout, TerminationRequested):
                raise
            except ContractError:
                raise
            except RuntimeError as error:
                last_observation_error = error
                actor = None
                state = "unavailable"
            now = self.monotonic()
            if actor is None:
                stable_running_reads = 0
                running_since = None
                if now >= deadline:
                    raise ContractError(
                        "EC2 fault restoration could not observe the exact instance within its bounded window"
                    ) from last_observation_error
                self.sleep(
                    min(
                        EC2_FAULT_RESTORE_POLL_SECONDS,
                        max(0.0, deadline - now),
                    )
                )
                continue
            if actor["actor_type"] != actor_type:
                raise MutationDenied(
                    "EC2 fault restoration target differs from immutable actor authority"
                )
            if phase == EC2_FAULT_STOP_CALL_ARMED and state in {"stopping", "stopped"}:
                phase = EC2_FAULT_STOP_OBSERVED
                self._set_fault_restoration_phase(actor_type, phase)
            # Running reads cannot settle an armed fault until a compensating
            # start call was armed, including in an earlier restoration attempt.
            if state == "running" and phase == EC2_FAULT_START_CALL_ARMED:
                if running_since is None:
                    running_since = now
                stable_running_reads += 1
                if (
                    stable_running_reads >= EC2_FAULT_RUNNING_STABLE_READS
                    and now - running_since >= EC2_FAULT_RUNNING_STABILITY_SECONDS
                    and now < deadline
                ):
                    self._set_fault_restoration_phase(
                        actor_type, EC2_FAULT_RUNNING_PROVED
                    )
                    return
            else:
                stable_running_reads = 0
                running_since = None
            if state == "stopped" and not start_attempted and phase in {
                EC2_FAULT_STOP_OBSERVED,
                EC2_FAULT_START_CALL_ARMED,
            }:
                start_timeout = deadline - self.monotonic()
                if start_timeout <= 0:
                    raise ContractError(
                        "EC2 fault restoration reached its deadline before restart"
                    )
                phase = EC2_FAULT_START_CALL_ARMED
                self._set_fault_restoration_phase(actor_type, phase)
                self._record_instance_actor(actor, "ec2:StartInstances")
                self.ledger.aws("ec2:StartInstances")
                start_attempted = True
                try:
                    self.aws.json(
                        ["ec2", "start-instances", "--instance-ids", instance_id],
                        region=region,
                        timeout_seconds=start_timeout,
                    )
                except (HardTimeout, CleanupTimeout, TerminationRequested):
                    raise
                except RuntimeError as error:
                    last_start_error = error
            elif state not in {"stopping", "stopped", "pending", "running"}:
                raise ContractError(
                    "EC2 fault restoration observed an unsupported instance state"
                )
            if now >= deadline:
                suffix = (
                    f" after {type(last_start_error).__name__}"
                    if last_start_error is not None
                    else ""
                )
                raise ContractError(
                    "EC2 fault restoration did not prove a stable running state"
                    + suffix
                )
            self.sleep(
                min(
                    EC2_FAULT_RESTORE_POLL_SECONDS,
                    max(0.0, deadline - now),
                )
            )

    def inject_router_failure(self, selection: Mapping[str, str]) -> Mapping[str, Any]:
        assert self.deployment is not None
        router = self.deployment.seed.routers_by_id[selection["router_id"]]
        instance_id = str(router["instance_id"])
        region = str(router["region"])
        actor = self._validate_instance_actor(
            instance_id, region, "ec2:StopInstances"
        )
        if actor["actor_type"] != "router":
            raise MutationDenied("router fault target differs from immutable actor authority")
        # Validation must be definite before process-local restoration is armed;
        # the phase is then retained across the runner's finally cleanup retry.
        self.failed_router_id = selection["router_id"]
        self.failed_router_instance = instance_id
        self._set_fault_restoration_phase("router", EC2_FAULT_STOP_CALL_ARMED)
        self._instance_fault(
            "stop", instance_id, region, validated_actor=actor
        )
        return {
            "domain_id": selection["domain_id"],
            "router_id": selection["router_id"],
            "alternate_router_id": selection["alternate_router_id"],
            "instance_id": router["instance_id"],
            "injected_at": utc_now(),
            "restored_at": None,
            "method": "ec2-stop-instance",
        }

    def _run_fresh_probe(
        self,
        protocol: str,
        stage: str,
        selection: Mapping[str, str],
        context: Mapping[str, str],
    ) -> dict[str, Any]:
        assert self.deployment is not None
        source_name, source, destination_name, destination = self._workload_pair(selection)
        source_site = source_name.split("-", 1)[0]
        region = str(self.deployment.seed.sites[source_site]["region"])
        started = utc_now()
        deadline = self.monotonic() + min(
            300, self.config.controller.timeouts["transition_seconds"]
        )
        attempts = 0
        flow_id = f"{self.config.run_id}-{stage}-{protocol}"
        success = False
        successful_flow_id = f"{flow_id}-unavailable"
        successful_connection_id = f"{successful_flow_id}:c0001"
        successful_source_port = 61000
        latency_milliseconds = 0
        while self.monotonic() < deadline and attempts < 128:
            attempts += 1
            source_port = 61000 + (0 if stage == "router-failover" else 200) + attempts * 2 + (
                0 if protocol == "tcp" else 1
            )
            attempt_flow_id = f"{flow_id}-{attempts}"
            command = " ".join(
                shlex.quote(part)
                for part in (
                    "/opt/envelope/e2e-agent",
                    "probe",
                    "--protocol",
                    protocol,
                    "--host",
                    destination["private_ip"],
                    "--port",
                    "5201",
                    "--source-ip",
                    source["private_ip"],
                    "--source-port",
                    str(source_port),
                    "--flow-id",
                    attempt_flow_id,
                    "--timeout",
                    "10",
                )
            )
            command_id = self._send_workload_command(
                source["instance_id"], region, command, timeout_seconds=30
            )
            result = self._wait_command(
                command_id,
                source["instance_id"],
                region,
                timeout_seconds=40,
            )
            if result.get("Status") == "Success":
                output = strict_json_loads(
                    str(result.get("StandardOutputContent", "")).strip(),
                    "workload probe output",
                )
                if not isinstance(output, Mapping):
                    raise ContractError("workload probe output must be an object")
                expected_keys = {
                    "connection_id",
                    "flow_id",
                    "latency_ns",
                    "local_ip",
                    "operation",
                    "protocol",
                    "sequence",
                    "source_port",
                    "success",
                }
                if set(output) != expected_keys:
                    raise ContractError("workload probe output has an unsupported shape")
                latency_ns = _integer(output["latency_ns"], "workload probe latency", 0)
                if (
                    output["success"] is True
                    and output["operation"] == "probe"
                    and output["protocol"] == protocol
                    and output["flow_id"] == attempt_flow_id
                    and output["connection_id"] == f"{attempt_flow_id}:c0001"
                    and output["local_ip"] == source["private_ip"]
                    and output["source_port"] == source_port
                    and output["sequence"] == 0
                ):
                    success = True
                    successful_flow_id = attempt_flow_id
                    successful_connection_id = str(output["connection_id"])
                    successful_source_port = source_port
                    latency_milliseconds = (latency_ns + 999_999) // 1_000_000
                    break
            self.sleep(1)
        event_at = canonical_timestamp(context.get("event_at"), "fresh flow event")
        convergence_at = canonical_timestamp(
            context.get("convergence_at"), "fresh flow convergence"
        )
        completed_at = utc_now()
        return {
            "stage": stage,
            "protocol": protocol,
            "attempts": attempts,
            "success": success,
            "flow_id_sha256": hash_identity(successful_flow_id),
            "connection_id_sha256": hash_identity(successful_connection_id),
            "started_at": started,
            "event_at": event_at,
            "convergence_at": convergence_at,
            "completed_at": completed_at,
            "recovery_milliseconds": int(
                (
                    parse_timestamp(completed_at, "fresh flow completed")
                    - parse_timestamp(event_at, "fresh flow event")
                ).total_seconds()
                * 1000
            ),
            "source_workload": source_name,
            "destination_workload": destination_name,
            "source_instance_id": source["instance_id"],
            "destination_instance_id": destination["instance_id"],
            "source_port": successful_source_port,
            "responder_acknowledged": success,
            "messages_sent": 1,
            "messages_received": 1 if success else 0,
            "loss_basis_points": 0 if success else 10_000,
            "latency_milliseconds": latency_milliseconds,
        }

    def probe_fresh_flows(
        self,
        stage: str,
        selection: Mapping[str, str],
        context: Mapping[str, str],
    ) -> Sequence[Mapping[str, Any]]:
        return [
            self._run_fresh_probe(protocol, stage, selection, context)
            for protocol in ("tcp", "udp")
        ]

    def inject_leader_failure(
        self, selection: Mapping[str, str], observation: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        assert self.controller_output is not None
        holder = _string(
            observation["dynamodb"]["lease_holder"], "selected domain lease holder", pattern=_ID_RE
        )
        fence = _integer(observation["dynamodb"]["fence_term"], "selected domain fence", 1)
        phase = _string(observation["dynamodb"]["phase"], "leader checkpoint phase")
        if phase not in {"route-intent-persisted", "routes-converging"}:
            raise ContractError("leader failure requires a durable in-progress route checkpoint")
        transaction = _mapping(
            observation["dynamodb"]["transaction"], "leader checkpoint transaction"
        )
        instances = _mapping(
            _output_value(self.controller_output, "controller_instances"),
            "controller instances",
        )
        instance = _mapping(instances.get(holder), "leader controller instance")
        instance_id = _string(instance.get("instance_id"), "leader instance ID", pattern=_INSTANCE_RE)
        actor = self._validate_instance_actor(
            instance_id, self.config.controller.region, "ec2:StopInstances"
        )
        if actor["actor_type"] != "controller" or actor["actor_id"] != holder:
            raise MutationDenied("leader fault target differs from immutable actor authority")
        self.failed_controller_id = holder
        self.failed_controller_instance = instance_id
        self._set_fault_restoration_phase("controller", EC2_FAULT_STOP_CALL_ARMED)
        self._instance_fault(
            "stop",
            instance_id,
            self.config.controller.region,
            validated_actor=actor,
        )
        return {
            "domain_id": selection["domain_id"],
            "previous_controller_id": holder,
            "new_controller_id": None,
            "instance_id": instance_id,
            "previous_fence": fence,
            "new_fence": 0,
            "injected_at": utc_now(),
            "method": "ec2-stop-instance",
            "checkpoint_phase": phase,
            "transaction_id_sha256": transaction["transaction_id_sha256"],
            "journaled_progress_count": sum(
                item["attempted"] or item["completed"] for item in transaction["progress"]
            ),
        }

    def observe_stale_fence_rejection(
        self,
        selection: Mapping[str, str],
        leader_fault: Mapping[str, Any],
        observation: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        raise ContractError(
            "stale-fence rejection requires a production rejection receipt and per-fence route-call counter"
        )

    def observe_ambiguous_settlement(
        self, selection: Mapping[str, str], observation: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        raise ContractError(
            "ambiguous settlement requires a deterministic external AWS-call fault injector"
        )

    def restore_router(self, fault: Mapping[str, Any]) -> Mapping[str, Any]:
        assert self.deployment is not None
        router = self.deployment.seed.routers_by_id[str(fault["router_id"])]
        if (
            self.failed_router_id != router["id"]
            or self.failed_router_instance != router["instance_id"]
        ):
            raise ContractError("router restoration target differs from the armed fault")
        self._restore_instance_fault(
            str(router["instance_id"]), str(router["region"]), "router"
        )
        return {"restored_at": utc_now()}

    def finish_established_flows(
        self, handle: Mapping[str, Any], context: Mapping[str, str]
    ) -> Sequence[Mapping[str, Any]]:
        commands = _mapping(handle.get("commands"), "established flow handles")
        sampled_at = canonical_timestamp(handle.get("sampled_at"), "established sampled_at")
        sampled_monotonic_ns = _integer(
            handle.get("sampled_monotonic_ns"), "established sample monotonic time", 1
        )
        source_workload = _string(
            handle.get("source_workload"), "established source workload", pattern=_ID_RE
        )
        destination_workload = _string(
            handle.get("destination_workload"),
            "established destination workload",
            pattern=_ID_RE,
        )
        source_instance_id = _string(
            handle.get("source_instance_id"),
            "established source instance",
            pattern=_INSTANCE_RE,
        )
        destination_instance_id = _string(
            handle.get("destination_instance_id"),
            "established destination instance",
            pattern=_INSTANCE_RE,
        )
        fault_at = canonical_timestamp(
            context.get("fault_injected_at"), "established fault time"
        )
        convergence_at = canonical_timestamp(
            context.get("convergence_at"), "established convergence time"
        )
        first_command = _mapping(commands.get("tcp"), "established TCP handle")
        sample_command = "python3 -c 'import json,time; print(json.dumps({\"monotonic_ns\":time.monotonic_ns()}))'"
        sample_id = self._send_established_command(
            str(first_command["instance_id"]),
            str(first_command["region"]),
            sample_command,
            timeout_seconds=30,
        )
        convergence_sample = self._wait_established_command(
            sample_id,
            str(first_command["instance_id"]),
            str(first_command["region"]),
            timeout_seconds=40,
        )
        if convergence_sample.get("Status") != "Success":
            raise ContractError("could not sample workload monotonic time after route convergence")
        convergence_clock = _mapping(
            strict_json_loads(
                str(convergence_sample.get("StandardOutputContent", "")).strip(),
                "post-convergence monotonic sample",
            ),
            "post-convergence monotonic sample",
        )
        _exact_keys(convergence_clock, {"monotonic_ns"}, "post-convergence monotonic sample")
        convergence_monotonic_ns = _integer(
            convergence_clock["monotonic_ns"], "post-convergence monotonic time", 1
        )
        evidence: list[dict[str, Any]] = []
        for protocol in ("tcp", "udp"):
            command = _mapping(commands.get(protocol), f"established {protocol} handle")
            _exact_keys(
                command,
                {
                    "command_id",
                    "instance_id",
                    "region",
                    "flow_id",
                    "source_ip",
                    "source_port",
                    "expected_markers",
                    "timeout_seconds",
                    "barrier_path",
                },
                f"established {protocol} handle",
            )
            command_id = _string(command["command_id"], "established command ID")
            instance_id = _string(
                command["instance_id"], "established command instance", pattern=_INSTANCE_RE
            )
            region = _string(command["region"], "established command region", pattern=_REGION_RE)
            completion_timeout = _integer(
                int(str(command["timeout_seconds"])),
                "established command completion timeout",
                1,
                ESTABLISHED_AGENT_MAX_TIMEOUT_SECONDS + 60,
            )
            result = self._wait_established_command(
                command_id,
                instance_id,
                region,
                timeout_seconds=completion_timeout,
            )
            if result.get("Status") not in SSM_TERMINAL_STATUSES:
                result = self._cancel_established_command(
                    command_id,
                    instance_id,
                    region,
                    timeout_seconds=60,
                )
            raw_output = str(result.get("StandardOutputContent", "")).strip()
            if not raw_output or len(raw_output.encode("utf-8")) >= SSM_STDOUT_MAX_BYTES:
                raise ContractError(
                    "established flow ended without parseable partial agent evidence; refusing inferred classification"
                )
            flow_id = _string(command["flow_id"], "established flow ID")
            source_port = _integer(
                int(str(command["source_port"])), "established source port", 1024, 65535
            )
            expected_markers = _integer(
                int(str(command["expected_markers"])),
                "expected established markers",
                2,
                ESTABLISHED_MAX_MARKERS,
            )
            parsed = parse_established_agent_output(
                strict_json_loads(raw_output, f"established {protocol} agent output"),
                protocol=protocol,
                flow_id=flow_id,
                source_ip=_string(command["source_ip"], "established source IP"),
                source_port=source_port,
                expected_markers=expected_markers,
                sampled_monotonic_ns=sampled_monotonic_ns,
                convergence_monotonic_ns=convergence_monotonic_ns,
            )
            classified_at = utc_now()
            evidence.append(
                {
                    "protocol": protocol,
                    "flow_id_sha256": hash_identity(flow_id),
                    "connection_id_sha256": hash_identity(f"{flow_id}:c0001"),
                    "source_workload": source_workload,
                    "destination_workload": destination_workload,
                    "source_instance_id": source_instance_id,
                    "destination_instance_id": destination_instance_id,
                    "source_port": source_port,
                    "sampled_at": sampled_at,
                    "fault_injected_at": fault_at,
                    "convergence_at": convergence_at,
                    "classified_at": classified_at,
                    **parsed,
                }
            )
        return evidence

    def restore_faults_for_cleanup(self) -> Mapping[str, Any]:
        errors: list[str] = []
        protected_secrets = getattr(self, "protected_secrets", ())
        router_phase = self._fault_restoration_phase("router")
        if router_phase not in {None, EC2_FAULT_RUNNING_PROVED}:
            if self.failed_router_id is None or self.deployment is None:
                errors.append("router restoration target is unavailable")
            else:
                router = self.deployment.seed.routers_by_id[self.failed_router_id]
                try:
                    self._restore_instance_fault(
                        str(router["instance_id"]), str(router["region"]), "router"
                    )
                except (HardTimeout, CleanupTimeout, TerminationRequested):
                    raise
                except Exception as error:
                    errors.append(
                        sanitize_text(
                            f"router restoration: {error}", protected_secrets
                        )
                    )
        controller_phase = self._fault_restoration_phase("controller")
        if controller_phase not in {None, EC2_FAULT_RUNNING_PROVED}:
            if self.failed_controller_instance is None:
                errors.append("controller restoration target is unavailable")
            else:
                try:
                    self._restore_instance_fault(
                        self.failed_controller_instance,
                        self.config.controller.region,
                        "controller",
                    )
                except (HardTimeout, CleanupTimeout, TerminationRequested):
                    raise
                except Exception as error:
                    errors.append(
                        sanitize_text(
                            f"controller restoration: {error}", protected_secrets
                        )
                    )

        commands = sorted(self.established_commands.items())
        for command_id, (instance_id, region) in commands:
            try:
                self.aws.json(
                    [
                        "ssm",
                        "cancel-command",
                        "--command-id",
                        command_id,
                        "--instance-ids",
                        instance_id,
                    ],
                    region=region,
                )
            except (HardTimeout, CleanupTimeout, TerminationRequested):
                raise
            except Exception as error:
                errors.append(
                    sanitize_text(
                        f"established command cancellation: {error}",
                        protected_secrets,
                    )
                )
        for command_id, (instance_id, region) in commands:
            try:
                result = self._wait_command(
                    command_id, instance_id, region, timeout_seconds=60
                )
                if result.get("Status") not in SSM_TERMINAL_STATUSES:
                    raise ContractError(
                        "established command remained nonterminal after cancellation"
                    )
                self.established_commands.pop(command_id, None)
            except (HardTimeout, CleanupTimeout, TerminationRequested):
                raise
            except Exception as error:
                errors.append(
                    sanitize_text(
                        f"established command termination: {error}",
                        protected_secrets,
                    )
                )
        if self.established_commands:
            errors.append("one or more established commands remain nonterminal")
        if errors:
            raise ContractError("; ".join(errors))
        return {"complete": True}

    def quiesce_controller(
        self, active_attempted: bool, active_succeeded: bool
    ) -> Mapping[str, Any]:
        if active_succeeded and not active_attempted:
            raise ContractError("active deployment success was recorded without an attempt")
        may_have_been_active = bool(
            active_attempted
            or active_succeeded
            or getattr(self, "active_deployment_attempted", False)
            or getattr(self, "controller_mode", None) == "active"
        )
        if self.controller_variables is None:
            if may_have_been_active:
                raise ContractError("cannot force read-only mode without controller variables")
            return {"complete": True}
        if may_have_been_active:
            self.deploy_controller("read-only", cleanup=True)
            self.sleep(self.config.controller.policy_seconds["lease_duration"])
        if may_have_been_active and self.deployment is not None:
            now = self.wall_clock()
            for domain in self.deployment.seed.domains:
                payload = self._dynamo_item(
                    f"deployment#{self.config.run_id}", f"domain#{domain['id']}"
                )
                lease = payload.get("lease") if isinstance(payload, Mapping) else None
                if isinstance(lease, Mapping) and parse_runtime_timestamp(
                    lease.get("expires_at"), "durable lease expiry"
                ) > now:
                    raise ContractError("controller lease remains live after read-only quiescence")
        return {"complete": True}

    def destroy_controller(self) -> Mapping[str, Any]:
        self.controller_workspace.destroy()
        self.controller_mode = None
        return {"complete": True}

    def delete_controller_material(self) -> Mapping[str, Any]:
        for reference in reversed(self.controller_parameters):
            self._delete_parameter(reference)
        for artifact in reversed(self.uploaded_objects):
            if not self._reconcile_uploaded_artifact(artifact):
                continue
            version_id = _string(
                artifact.get("version_id"), "controller artifact cleanup version ID"
            )
            self.aws.json(
                [
                    "s3api",
                    "delete-object",
                    "--bucket",
                    artifact["bucket"],
                    "--key",
                    artifact["key"],
                    "--version-id",
                    version_id,
                ],
                region=artifact["region"],
            )
            if any(
                version["version_id"] == version_id
                for version in self._artifact_version_delta(artifact)
            ):
                raise ContractError(
                    "run-owned controller artifact version remains after deletion"
                )
            artifact["version_id"] = None
        return {"complete": True}

    def destroy_appliance(self) -> Mapping[str, Any]:
        self.appliance_workspace.destroy()
        return {"complete": True}

    def _expected_tailnet_device_names(self) -> set[str]:
        expected: set[str] = set()
        if self.appliance_deployment_started or self.appliance_workspace.variables_path.is_file():
            expected.update(
                f"{self.config.run_id}-{site}-transport-{az_key}"
                for site in ("west", "east")
                for az_key in self.config.appliance.sites[site]["transport_router_az_keys"]
            )
        if self.controller_workspace.variables_path.is_file():
            expected.update(self.config.controller.controller_ids)
        return expected

    def cleanup_tailnet(self) -> Mapping[str, Any]:
        expected = self._expected_tailnet_device_names()
        if expected:
            if not self.tailnet_baseline_captured:
                raise ContractError(
                    "cannot clean Tailnet devices without the pre-mutation ID baseline"
                )
            self.ledger.tailnet("tailscale:ListDevices")
            devices = self.tailnet.list_devices()
            selected = self._post_baseline_tailnet_devices(devices)
            selected_ids = {str(device["id"]) for device in selected}
            known_remaining = self.tailnet_owned_device_ids.intersection(
                self._tailnet_ids(devices, "Tailnet cleanup device")
            )
            if known_remaining - selected_ids:
                raise ContractError(
                    "known run-owned Tailnet device lost its exact name or tag identity"
                )
            for device in selected:
                self.ledger.tailnet("tailscale:DeleteDevice")
                self.tailnet.delete_device(
                    _string(device.get("id"), "Tailnet cleanup device ID")
                )
        auth_key_ids = set(self.created_auth_key_ids)
        if self.tailnet_baseline_captured:
            self.ledger.tailnet("tailscale:ListAuthKeys")
            auth_key_ids.update(
                self._post_baseline_auth_key_ids(self.tailnet.list_auth_keys())
            )
        for auth_key_id in sorted(auth_key_ids):
            self.ledger.tailnet("tailscale:RevokeAuthKey")
            self.tailnet.revoke_auth_key(auth_key_id)
        self.router_key_id = None
        for reference in reversed(self.router_parameters):
            self._delete_parameter(reference)
        if expected:
            self.ledger.tailnet("tailscale:ListDevices")
            remaining = self.tailnet.list_devices()
            remaining_ids = self._tailnet_ids(
                remaining, "Tailnet post-cleanup device"
            )
            if self._post_baseline_tailnet_devices(
                remaining
            ) or self.tailnet_owned_device_ids.intersection(remaining_ids):
                raise ContractError("run-scoped Tailnet devices remain after cleanup")
        if self.tailnet_baseline_captured:
            self.ledger.tailnet("tailscale:ListAuthKeys")
            remaining_auth_keys = self.tailnet.list_auth_keys()
            remaining_auth_ids = self._tailnet_ids(
                remaining_auth_keys, "Tailnet post-cleanup auth key"
            )
            if self._post_baseline_auth_key_ids(
                remaining_auth_keys
            ) or auth_key_ids.intersection(remaining_auth_ids):
                raise ContractError("run-scoped Tailnet auth keys remain after cleanup")
        return {"complete": True}

    def audit_residuals(self) -> Sequence[Mapping[str, Any]]:
        regions = {
            self.config.controller.region,
            *(str(self.config.appliance.sites[site]["region"]) for site in ("west", "east")),
        }
        resources: set[str] = set()
        for region in sorted(regions):
            response = self.aws.json(
                [
                    "resourcegroupstaggingapi",
                    "get-resources",
                    "--tag-filters",
                    f"Key=EnvelopeRun,Values={self.config.run_id}",
                ],
                region=region,
            )
            mappings = response.get("ResourceTagMappingList")
            if not isinstance(mappings, list):
                raise ContractError("AWS residual audit returned an invalid resource list")
            resources.update(
                str(item["ResourceARN"])
                for item in mappings
                if isinstance(item, Mapping) and isinstance(item.get("ResourceARN"), str)
            )
        parameter_count = self._parameter_residual_count()
        artifact_version_count = 0
        for artifact in self.uploaded_objects:
            artifact_version_count += len(self._artifact_version_delta(artifact))
        expected_names = self._expected_tailnet_device_names()
        self.ledger.tailnet("tailscale:ListDevices")
        devices = self.tailnet.list_devices()
        device_ids = self._tailnet_ids(devices, "Tailnet residual device")
        tailnet_count = len(
            {
                *(str(device["id"]) for device in self._post_baseline_tailnet_devices(devices)),
                *self.tailnet_owned_device_ids.intersection(device_ids),
            }
        ) if expected_names else 0
        self.ledger.tailnet("tailscale:ListAuthKeys")
        auth_keys = self.tailnet.list_auth_keys()
        remaining_key_ids = self._tailnet_ids(
            auth_keys, "Tailnet residual auth key"
        )
        auth_key_count = len(
            remaining_key_ids.intersection(self.created_auth_key_ids)
            | self._post_baseline_auth_key_ids(auth_keys)
        )
        return [
            {"hook": "aws-tagged-resources", "residual_count": len(resources)},
            {"hook": "ssm-secret-references", "residual_count": parameter_count},
            {
                "hook": "controller-artifact-versions",
                "residual_count": artifact_version_count,
            },
            {"hook": "tailnet-devices", "residual_count": tailnet_count},
            {"hook": "tailscale-auth-keys", "residual_count": auth_key_count},
        ]

    def finalize_backend(self) -> Mapping[str, Any]:
        bucket, region, claim_key, claim_version_id = self._require_backend_claim()
        if not getattr(self, "backend_state_cleanup_authorized", False):
            raise ContractError(
                "backend state deletion was not authorized by an empty post-claim check"
            )
        for key in self._backend_state_keys():
            self._require_backend_claim()
            delete_exact_object_versions(
                self.aws,
                bucket=bucket,
                key=key,
                region=region,
                dry_run=False,
            )
            self._require_backend_claim()
        self._require_backend_claim()
        self.aws.json(
            [
                "s3api",
                "delete-object",
                "--bucket",
                bucket,
                "--key",
                claim_key,
                "--version-id",
                claim_version_id,
            ],
            region=region,
        )
        if exact_object_versions(
            self.aws, bucket=bucket, key=claim_key, region=region
        ):
            raise ContractError("backend run claim remains after exact-version deletion")
        self.backend_claim_version_id = None
        self.backend_state_cleanup_authorized = False
        return {"complete": True}


def _load_evidence(path: pathlib.Path) -> dict[str, Any]:
    return _mapping(load_json(path, "production controller evidence"), "production controller evidence")


def established_stream_duration_seconds(config: ProductionRunConfig) -> int:
    return (
        ESTABLISHED_STREAM_TRANSITIONS
        * config.controller.timeouts["transition_seconds"]
        + ESTABLISHED_STREAM_MARGIN_SECONDS
    )


def validate_protected_budgets(
    config: ProductionRunConfig,
    *,
    hard_timeout_seconds: int,
    aws_role_duration_seconds: int,
    job_timeout_seconds: int,
) -> None:
    hard_timeout_seconds = _integer(
        hard_timeout_seconds,
        "hard timeout",
        60,
        AWS_MAX_ROLE_DURATION_SECONDS,
    )
    aws_role_duration_seconds = _integer(
        aws_role_duration_seconds,
        "AWS role duration",
        900,
        AWS_MAX_ROLE_DURATION_SECONDS,
    )
    job_timeout_seconds = _integer(
        job_timeout_seconds,
        "job timeout",
        60,
        AWS_MAX_ROLE_DURATION_SECONDS,
    )
    if established_stream_duration_seconds(config) + OBSERVATION_MARGIN_SECONDS >= hard_timeout_seconds:
        raise ContractError(
            "hard timeout does not contain the established-flow scenario window"
        )
    protected_reservation = (
        hard_timeout_seconds
        + config.controller.timeouts["cleanup_seconds"]
        + PROTECTED_SETUP_SAFETY_MARGIN_SECONDS
    )
    if protected_reservation > aws_role_duration_seconds:
        raise ContractError(
            "hard timeout, cleanup, and setup safety margin exceed the AWS role duration"
        )
    if protected_reservation > job_timeout_seconds:
        raise ContractError(
            "hard timeout, cleanup, and setup safety margin exceed the job timeout"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_config = subparsers.add_parser("validate-config")
    validate_config.add_argument("path", type=pathlib.Path)
    parse_output = subparsers.add_parser("parse-appliance-output")
    parse_output.add_argument("path", type=pathlib.Path)
    parse_output.add_argument("--config", required=True, type=pathlib.Path)
    for name in ("validate-evidence", "verify-evidence", "scan-evidence"):
        command = subparsers.add_parser(name)
        command.add_argument("path", type=pathlib.Path)
    run = subparsers.add_parser("run-all")
    run.add_argument("--config", required=True, type=pathlib.Path)
    run.add_argument("--run-root", type=pathlib.Path, default=pathlib.Path(".run"))
    run.add_argument(
        "--appliance-terraform-dir",
        type=pathlib.Path,
        default=pathlib.Path("example/terraform"),
    )
    run.add_argument(
        "--controller-terraform-dir",
        type=pathlib.Path,
        default=pathlib.Path("deploy/terraform/envelope-controller"),
    )
    run.add_argument("--evidence", type=pathlib.Path)
    run.add_argument(
        "--hard-timeout-seconds",
        type=int,
        default=10800,
        help="bounded acceptance window before the runner begins ordered cleanup",
    )
    run.add_argument(
        "--aws-role-duration-seconds",
        type=int,
        default=DEFAULT_AWS_ROLE_DURATION_SECONDS,
        help="reviewed AWS role session duration containing acceptance and cleanup",
    )
    run.add_argument(
        "--job-timeout-seconds",
        type=int,
        default=DEFAULT_JOB_TIMEOUT_SECONDS,
        help="reviewed workflow job duration containing acceptance and cleanup",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    protected_secrets: tuple[str, ...] = ()
    try:
        if args.command == "validate-config":
            config = ProductionRunConfig.load(args.path, enforce_future_expiry=False)
            print(
                json.dumps(
                    {
                        "run_id": config.run_id,
                        "schema": 3,
                        "state_keys_distinct": True,
                        "valid": True,
                    },
                    sort_keys=True,
                )
            )
            return EXIT_OK
        if args.command == "parse-appliance-output":
            config = ProductionRunConfig.load(args.config, enforce_future_expiry=False)
            deployment = parse_appliance_output(load_json(args.path, "appliance output"), config)
            print(
                json.dumps(
                    {
                        "domain_count": len(deployment.seed.domains),
                        "output_sha256": deployment.output_sha256,
                        "router_count": len(deployment.seed.routers),
                        "valid": True,
                    },
                    sort_keys=True,
                )
            )
            return EXIT_OK
        if args.command == "validate-evidence":
            evidence = validate_evidence(_load_evidence(args.path))
            print(json.dumps({"kind": evidence["kind"], "schema": evidence["schema"], "valid": True}, sort_keys=True))
            return EXIT_OK
        if args.command == "verify-evidence":
            evidence = verify_evidence(_load_evidence(args.path))
            print(json.dumps({"run_id": evidence["run_id"], "verified": True}, sort_keys=True))
            return EXIT_OK
        if args.command == "scan-evidence":
            findings = scan_evidence(_load_evidence(args.path))
            print(json.dumps({"findings": findings, "safe": not findings}, sort_keys=True))
            return EXIT_OK if not findings else EXIT_CONTRACT_ERROR
        if args.command == "run-all":
            config = ProductionRunConfig.load(args.config)
            protected_secrets = protected_environment_secrets(config)
            validate_protected_budgets(
                config,
                hard_timeout_seconds=args.hard_timeout_seconds,
                aws_role_duration_seconds=args.aws_role_duration_seconds,
                job_timeout_seconds=args.job_timeout_seconds,
            )
            run_root = args.run_root.expanduser().resolve()
            run_dir = (run_root / config.run_id).resolve()
            if run_dir.parent != run_root:
                raise ContractError("approved run directory escaped the run root")
            evidence_path = (
                run_dir / "aws-production-controller-e2e-evidence.json"
                if args.evidence is None
                else args.evidence.expanduser().resolve()
            )
            if evidence_path.parent != run_dir:
                raise ContractError("evidence must remain directly inside the approved run directory")
            expiry = parse_timestamp(config.expires_at, "expires_at")
            required = (
                args.hard_timeout_seconds
                + config.controller.timeouts["cleanup_seconds"]
                + PROTECTED_SETUP_SAFETY_MARGIN_SECONDS
            )
            if expiry <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=required):
                raise ContractError("run expiry does not reserve acceptance and cleanup timeouts")
            adapter = AwsProductionAdapter(
                config,
                run_dir,
                args.appliance_terraform_dir,
                args.controller_terraform_dir,
            )
            if not hasattr(signal, "SIGALRM") or not hasattr(signal, "pthread_sigmask"):
                raise ContractError(
                    "protected run hard timeout requires POSIX alarms and signal masking"
                )
            with ProtectedLifecycleDeadline(
                args.hard_timeout_seconds,
                config.controller.timeouts["cleanup_seconds"],
            ) as lifecycle:
                result = ProductionControllerRunner(
                    config,
                    adapter,
                    evidence_path,
                    begin_cleanup=lifecycle.start_cleanup,
                    finish_cleanup=lifecycle.finish_cleanup,
                ).run()
            print(
                json.dumps(
                    {
                        "evidence": str(evidence_path),
                        "exit_code": result.exit_code,
                        "run_id": config.run_id,
                        "status": result.evidence["status"],
                    },
                    sort_keys=True,
                )
            )
            return result.exit_code
        raise ContractError("unsupported command")
    except (HardTimeout, CleanupTimeout, TerminationRequested) as error:
        print(sanitize_text(error, protected_secrets), file=sys.stderr)
        return EXIT_CLEANUP_FAILED
    except EvidenceError as error:
        print(sanitize_text(error, protected_secrets), file=sys.stderr)
        return EXIT_ACCEPTANCE_FAILED
    except (ContractError, OSError, RuntimeError) as error:
        print(sanitize_text(error, protected_secrets), file=sys.stderr)
        return EXIT_CONTRACT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
