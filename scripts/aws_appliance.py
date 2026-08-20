#!/usr/bin/env python3
"""Protected lifecycle tooling for the two-region Envelope appliance example."""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import contextlib
import dataclasses
import datetime as dt
import fcntl
import fnmatch
import functools
import hashlib
import http.client
import inspect
import ipaddress
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Iterable, Protocol

from inspect_artifact import inspect as inspect_artifact
from validate_appliance_plan import validate as validate_saved_plan


SCHEMA = 2
ARCHITECTURES = {"amd64": "x86_64", "arm64": "arm64"}
TAILSCALE_VERSION = "1.80.3"
SECRET_PATTERNS = (
    re.compile(r"tskey-[A-Za-z0-9_-]+", re.IGNORECASE),
    re.compile(r"(?i)(access[_-]?key|secret|token|auth[_-]?key)([\"'= :]+)([^\s,\"'}]+)"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
)
RUN_RE = re.compile(r"^[a-z][a-z0-9-]{2,17}[a-z0-9]$")


def redact(value: str) -> str:
    result = value
    result = SECRET_PATTERNS[0].sub("[REDACTED_TAILSCALE_KEY]", result)
    result = SECRET_PATTERNS[1].sub(r"\1\2[REDACTED]", result)
    result = SECRET_PATTERNS[2].sub("[REDACTED_AWS_ACCESS_KEY]", result)
    return result


class LifecycleError(RuntimeError):
    pass


class CommandError(LifecycleError):
    def __init__(self, args: list[str], returncode: int, stderr: str):
        safe_command = " ".join(shlex.quote(part) for part in args)
        super().__init__(redact(f"command failed ({returncode}): {safe_command}: {stderr.strip()}"))
        self.args_list = args
        self.returncode = returncode
        self.raw_stderr = stderr


class CommandRunner(Protocol):
    def run(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: pathlib.Path | None = None,
        input_text: str | None = None,
    ) -> str: ...


class SubprocessRunner:
    def __init__(self, excluded_environment: Iterable[str] = ()):
        self.excluded_environment = frozenset(excluded_environment)

    def run(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: pathlib.Path | None = None,
        input_text: str | None = None,
    ) -> str:
        child_env = os.environ.copy() if env is None else dict(env)
        for name in self.excluded_environment:
            child_env.pop(name, None)
        completed = subprocess.run(
            args,
            cwd=cwd,
            env=child_env,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode:
            raise CommandError(args, completed.returncode, completed.stderr)
        return completed.stdout


_LIFECYCLE_LOCKS: dict[pathlib.Path, threading.RLock] = {}
_LIFECYCLE_LOCKS_GUARD = threading.Lock()
_LIFECYCLE_LOCK_DEPTH = threading.local()


@contextlib.contextmanager
def lifecycle_lock(run_dir: pathlib.Path) -> Iterable[None]:
    run_dir = run_dir.expanduser().resolve()
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = run_dir / "lifecycle.lock"
    with _LIFECYCLE_LOCKS_GUARD:
        local_lock = _LIFECYCLE_LOCKS.setdefault(path, threading.RLock())
    with local_lock:
        depths = getattr(_LIFECYCLE_LOCK_DEPTH, "values", {})
        depth = depths.get(path, 0)
        if depth:
            depths[path] = depth + 1
            _LIFECYCLE_LOCK_DEPTH.values = depths
            try:
                yield
            finally:
                depths[path] -= 1
            return
        with path.open("a") as stream:
            os.chmod(path, 0o600)
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise LifecycleError("another protected lifecycle operation is already running") from error
            depths[path] = 1
            _LIFECYCLE_LOCK_DEPTH.values = depths
            try:
                yield
            finally:
                depths.pop(path, None)
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def serialized_run_operation(function: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        bound = inspect.signature(function).bind(*args, **kwargs)
        run_dir = bound.arguments.get("run_dir")
        if not isinstance(run_dir, pathlib.Path):
            raise LifecycleError("protected lifecycle operation has no run directory")
        with lifecycle_lock(run_dir):
            return function(*args, **kwargs)

    return wrapped


class AwsCLI:
    def __init__(self, runner: CommandRunner, excluded_environment: Iterable[str] = ()):
        self.runner = runner
        self.excluded_environment = frozenset(excluded_environment)

    def call(self, args: list[str], *, region: str | None = None) -> str:
        command = ["aws"]
        if region:
            command.extend(["--region", region])
        command.extend(args)
        command.extend(["--no-cli-pager", "--output", "json"])
        env = os.environ.copy()
        env["AWS_PAGER"] = ""
        for name in self.excluded_environment:
            env.pop(name, None)
        return self.runner.run(command, env=env)

    def json(self, args: list[str], *, region: str | None = None) -> dict[str, Any]:
        output = self.call(args, region=region)
        if not output.strip():
            return {}
        try:
            parsed = json.loads(output)
        except json.JSONDecodeError as error:
            raise LifecycleError(f"AWS CLI returned invalid JSON: {error}") from error
        if not isinstance(parsed, dict):
            raise LifecycleError("AWS CLI returned a non-object JSON response")
        return parsed

    def object_exists(self, bucket: str, key: str, region: str) -> bool:
        try:
            self.json(["s3api", "head-object", "--bucket", bucket, "--key", key], region=region)
            return True
        except CommandError as error:
            if any(marker in error.raw_stderr for marker in ("(404)", "Not Found", "NoSuchKey")):
                return False
            raise


class HTTPTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, bytes]: ...


class UrllibTransport:
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, bytes]:
        request = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()


class TailscaleAPI:
    def __init__(self, tailnet: str, client_id: str, client_secret: str, transport: HTTPTransport):
        if not client_id or not client_secret:
            raise LifecycleError("scoped Tailscale OAuth credentials are required in protected environment variables")
        self.tailnet = tailnet
        self.client_id = client_id
        self.client_secret = client_secret
        self.transport = transport
        self._token: str | None = None
        self.base_url = "https://api.tailscale.com/api/v2"

    def _oauth_token(self) -> str:
        if self._token:
            return self._token
        basic = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
        status, body = self.transport.request(
            "POST",
            f"{self.base_url}/oauth/token",
            headers={
                "Authorization": f"Basic {basic}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body=urllib.parse.urlencode({"grant_type": "client_credentials"}).encode(),
        )
        response = self._decode(status, body, "obtain OAuth token")
        token = response.get("access_token")
        if not isinstance(token, str) or not token:
            raise LifecycleError("Tailscale OAuth response omitted access_token")
        self._token = token
        return token

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        status, response = self.transport.request(
            method,
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {self._oauth_token()}", "Content-Type": "application/json"},
            body=body,
        )
        return self._decode(status, response, f"Tailscale API {method} {path}")

    @staticmethod
    def _decode(status: int, body: bytes, operation: str) -> dict[str, Any]:
        if status < 200 or status >= 300:
            message = body.decode(errors="replace")[:512]
            raise LifecycleError(redact(f"{operation} failed with HTTP {status}: {message}"))
        if not body.strip():
            return {}
        try:
            value = json.loads(body)
        except json.JSONDecodeError as error:
            raise LifecycleError(f"{operation} returned invalid JSON") from error
        if not isinstance(value, dict):
            raise LifecycleError(f"{operation} returned a non-object response")
        return value

    def policy_text(self) -> str:
        token = self._oauth_token()
        path = f"/tailnet/{urllib.parse.quote(self.tailnet, safe='')}/acl"
        status, body = self.transport.request(
            "GET",
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/hujson"},
        )
        if status < 200 or status >= 300:
            raise LifecycleError(f"read Tailnet policy failed with HTTP {status}")
        return body.decode()

    def list_devices(self) -> list[dict[str, Any]]:
        response = self._request("GET", f"/tailnet/{urllib.parse.quote(self.tailnet, safe='')}/devices?fields=all")
        devices = response.get("devices", [])
        if not isinstance(devices, list):
            raise LifecycleError("Tailscale device response omitted devices list")
        return [device for device in devices if isinstance(device, dict)]

    def list_auth_keys(self) -> list[dict[str, Any]]:
        response = self._request("GET", f"/tailnet/{urllib.parse.quote(self.tailnet, safe='')}/keys")
        keys = response.get("keys", [])
        if not isinstance(keys, list):
            raise LifecycleError("Tailscale auth-key response omitted keys list")
        return [key for key in keys if isinstance(key, dict)]

    def create_auth_key(self, tag: str, description: str, expiry_seconds: int) -> tuple[str, str]:
        response = self._request(
            "POST",
            f"/tailnet/{urllib.parse.quote(self.tailnet, safe='')}/keys",
            {
                "capabilities": {
                    "devices": {
                        "create": {
                            "reusable": True,
                            "ephemeral": True,
                            "preauthorized": True,
                            "tags": [tag],
                        }
                    }
                },
                "expirySeconds": expiry_seconds,
                "description": description,
            },
        )
        key_id, key = response.get("id"), response.get("key")
        if not isinstance(key_id, str) or not key_id or not isinstance(key, str) or not key:
            raise LifecycleError("Tailscale key creation response omitted key id or material")
        return key_id, key

    def revoke_auth_key(self, key_id: str) -> None:
        path = f"/tailnet/{urllib.parse.quote(self.tailnet, safe='')}/keys/{urllib.parse.quote(key_id, safe='')}"
        status, body = self.transport.request(
            "DELETE",
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {self._oauth_token()}"},
        )
        if status == 404 or 200 <= status < 300:
            return
        self._decode(status, body, "revoke Tailscale auth key")

    def delete_device(self, device_id: str) -> None:
        path = f"/device/{urllib.parse.quote(device_id, safe='')}"
        status, body = self.transport.request(
            "DELETE",
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {self._oauth_token()}"},
        )
        if status == 404 or 200 <= status < 300:
            return
        self._decode(status, body, "delete Tailscale device")


def parse_hujson(value: str) -> dict[str, Any]:
    output: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(value):
        char = value[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if value[index : index + 2] == "//":
            index = value.find("\n", index)
            if index < 0:
                break
            output.append("\n")
            index += 1
            continue
        if value[index : index + 2] == "/*":
            end = value.find("*/", index + 2)
            if end < 0:
                raise LifecycleError("Tailnet policy has an unterminated block comment")
            index = end + 2
            continue
        output.append(char)
        index += 1
    normalized = "".join(output)
    normalized = re.sub(r"([,{]\s*)([A-Za-z][A-Za-z0-9_-]*)(\s*:)", r'\1"\2"\3', normalized)
    normalized = re.sub(r",(\s*[}\]])", r"\1", normalized)
    try:
        parsed = json.loads(normalized)
    except json.JSONDecodeError as error:
        raise LifecycleError(f"Tailnet policy is not parseable HuJSON: line {error.lineno}") from error
    if not isinstance(parsed, dict):
        raise LifecycleError("Tailnet policy must be an object")
    return parsed


def network_covers(candidate: str, required: str) -> bool:
    try:
        parent = ipaddress.ip_network(candidate, strict=False)
        child = ipaddress.ip_network(required, strict=False)
    except ValueError:
        return False
    return parent.version == child.version and child.subnet_of(parent)


def policy_endpoint_covers(candidate: str, required: str) -> bool:
    if candidate == "*":
        return True
    if network_covers(candidate, required):
        return True
    if candidate.startswith("[") and "]:" in candidate:
        candidate = candidate[1 : candidate.rfind("]:")]
    elif candidate.count(":") == 1 and "/" in candidate:
        candidate = candidate.rsplit(":", 1)[0]
    return network_covers(candidate, required)


def validate_tailnet_policy(
    policy: dict[str, Any],
    *,
    tag: str,
    tag_owners: Iterable[str],
    advertised_routes: Iterable[str],
    lane_cidrs: dict[str, list[str]],
    snat_subnet_routes: bool,
) -> None:
    errors: list[str] = []
    if snat_subnet_routes:
        errors.append("subnet-route SNAT must be disabled")
    owners = policy.get("tagOwners", {}).get(tag, []) if isinstance(policy.get("tagOwners"), dict) else []
    if not isinstance(owners, list) or not set(tag_owners).issubset(set(str(owner) for owner in owners)):
        errors.append(f"tagOwners for {tag} do not include every required owner")
    auto = policy.get("autoApprovers", {})
    routes = auto.get("routes", {}) if isinstance(auto, dict) else {}
    if not isinstance(routes, dict):
        routes = {}
    for required in advertised_routes:
        approved = any(
            network_covers(str(candidate), required)
            and isinstance(approvers, list)
            and tag in [str(approver) for approver in approvers]
            for candidate, approvers in routes.items()
        )
        if not approved:
            errors.append(f"route autoApprovers do not authorize {tag} for {required}")
    grants = policy.get("grants", [])
    if not isinstance(grants, list):
        grants = []
    for source_site, destination_site in (("west", "east"), ("east", "west")):
        for source in lane_cidrs[source_site]:
            for destination in lane_cidrs[destination_site]:
                allowed = False
                for grant in grants:
                    if not isinstance(grant, dict):
                        continue
                    sources = grant.get("src", [])
                    destinations = grant.get("dst", [])
                    protocols = grant.get("ip", [])
                    if not all(isinstance(item, list) for item in (sources, destinations, protocols)):
                        continue
                    if (
                        "*" in protocols
                        and any(policy_endpoint_covers(str(item), source) for item in sources)
                        and any(policy_endpoint_covers(str(item), destination) for item in destinations)
                    ):
                        allowed = True
                        break
                if not allowed:
                    errors.append(f"grants do not allow {source} to {destination}")
    if errors:
        raise LifecycleError("Tailnet policy preflight failed: " + "; ".join(errors))


@dataclasses.dataclass(frozen=True)
class RunConfig:
    path: pathlib.Path
    raw: dict[str, Any]
    run_id: str
    expires_at: str
    backend: dict[str, Any]
    sites: dict[str, dict[str, Any]]
    tailnet: dict[str, Any]
    architecture: str
    artifact_manifest: pathlib.Path

    @classmethod
    def load(cls, path: pathlib.Path, *, enforce_future_expiry: bool = True) -> "RunConfig":
        path = path.expanduser().resolve()
        try:
            raw = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise LifecycleError(f"cannot read run config {path}: {error}") from error
        if not isinstance(raw, dict):
            raise LifecycleError("run config must be a JSON object")
        top_level_keys = {
            "run_id",
            "expires_at",
            "architecture",
            "artifact_manifest",
            "instance_type",
            "test_instance_type",
            "ebs_root_volume_size",
            "tailscale_version",
            "tags",
            "backend",
            "sites",
            "tailnet",
            "envelope",
            "cost",
        }
        if set(raw) - top_level_keys:
            raise LifecycleError(f"run config has unsupported fields: {sorted(set(raw) - top_level_keys)}")
        run_id = str(raw.get("run_id", ""))
        if not RUN_RE.fullmatch(run_id):
            raise LifecycleError("run_id must satisfy the Terraform name contract")
        expires_at = str(raw.get("expires_at", ""))
        try:
            expiry = dt.datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise LifecycleError("expires_at must be RFC3339") from error
        if expiry.tzinfo is None:
            raise LifecycleError("expires_at must include a timezone")
        if enforce_future_expiry:
            now = dt.datetime.now(dt.timezone.utc)
            if expiry <= now + dt.timedelta(minutes=30) or expiry > now + dt.timedelta(hours=24):
                raise LifecycleError("expires_at must be 30 minutes to 24 hours in the future for a new run")
        backend = raw.get("backend")
        sites = raw.get("sites")
        tailnet = raw.get("tailnet")
        architecture = str(raw.get("architecture", ""))
        if not isinstance(backend, dict) or not isinstance(sites, dict) or not isinstance(tailnet, dict):
            raise LifecycleError("backend, sites, and tailnet objects are required")
        backend_keys = {"bucket", "region", "kms_key_arn", "state_key", "operator_principal_arns"}
        if set(backend) - backend_keys:
            raise LifecycleError(f"backend has unsupported fields: {sorted(set(backend) - backend_keys)}")
        if set(sites) != {"west", "east"}:
            raise LifecycleError("sites must contain exactly west and east")
        if not all(isinstance(sites[site], dict) for site in ("west", "east")):
            raise LifecycleError("each site must be an object")
        if architecture not in ARCHITECTURES:
            raise LifecycleError("architecture must be amd64 or arm64")
        for key in ("bucket", "region", "kms_key_arn", "operator_principal_arns"):
            if not backend.get(key):
                raise LifecycleError(f"backend.{key} is required")
        if not re.fullmatch(r"arn:aws(?:-[a-z]+)?:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+", str(backend["kms_key_arn"])):
            raise LifecycleError("backend.kms_key_arn must be an exact KMS key ARN")
        state_key = str(backend.get("state_key", f"runs/{run_id}/terraform.tfstate"))
        if state_key != f"runs/{run_id}/terraform.tfstate":
            raise LifecycleError("backend.state_key must be the unique run-owned key")
        principals = backend.get("operator_principal_arns")
        if not isinstance(principals, list) or not principals or not all(
            isinstance(value, str) and re.fullmatch(r"arn:aws(?:-[a-z]+)?:iam::[0-9]{12}:(?:role|user)/[^*]+", value)
            for value in principals
        ):
            raise LifecycleError("backend.operator_principal_arns must list exact IAM role/user ARNs")
        normalized_backend = {str(key): str(value) for key, value in backend.items() if key != "operator_principal_arns"}
        normalized_backend["state_key"] = state_key
        normalized_backend["operator_principal_arns"] = [str(value) for value in principals]
        backend = normalized_backend

        normalized_sites: dict[str, dict[str, Any]] = {}
        site_networks: dict[str, ipaddress._BaseNetwork] = {}
        for site in ("west", "east"):
            value = sites[site]
            required = (
                "region",
                "ami_id",
                "ssm_kms_key_arn",
                "azs",
                "appliance_az_key",
                "vpc_cidr",
                "public_subnet_cidr",
                "appliance_subnet_cidr",
                "workload_subnet_cidrs",
                "gwlbe_subnet_cidrs",
                "gwlb_subnet_cidrs",
                "gwlb_return_cidrs",
                "local_delivery_cidrs",
            )
            if set(value) - set(required):
                raise LifecycleError(f"sites.{site} has unsupported fields: {sorted(set(value) - set(required))}")
            if not all(value.get(key) for key in required):
                raise LifecycleError(f"sites.{site} is missing a required region, image, AZ, subnet, or lane input")
            if not re.fullmatch(r"ami-[0-9a-f]{8,17}", str(value["ami_id"])):
                raise LifecycleError(f"sites.{site}.ami_id must be an explicit AMI ID")
            region = str(value["region"])
            kms_pattern = rf"arn:aws(?:-[a-z]+)?:kms:{re.escape(region)}:[0-9]{{12}}:key/[A-Za-z0-9-]+"
            if not re.fullmatch(kms_pattern, str(value["ssm_kms_key_arn"])):
                raise LifecycleError(f"sites.{site}.ssm_kms_key_arn must be an exact regional KMS key ARN")
            azs = value["azs"]
            if not isinstance(azs, dict) or not 1 <= len(azs) <= 3 or not all(
                isinstance(key, str)
                and re.fullmatch(r"[a-z][a-z0-9-]{0,7}", key)
                and isinstance(zone, str)
                and zone.startswith(region)
                for key, zone in azs.items()
            ) or len(set(azs.values())) != len(azs):
                raise LifecycleError(f"sites.{site}.azs must contain one to three unique explicit regional AZs")
            appliance_key = str(value["appliance_az_key"])
            if appliance_key not in azs:
                raise LifecycleError(f"sites.{site}.appliance_az_key must name a configured AZ key")
            role_maps: dict[str, dict[str, str]] = {}
            for field in ("workload_subnet_cidrs", "gwlbe_subnet_cidrs", "gwlb_subnet_cidrs"):
                candidate = value[field]
                if not isinstance(candidate, dict) or set(candidate) != set(azs):
                    raise LifecycleError(f"sites.{site}.{field} must use exactly the configured AZ keys")
                role_maps[field] = {str(key): str(cidr) for key, cidr in candidate.items()}
            try:
                vpc = ipaddress.ip_network(str(value["vpc_cidr"]), strict=True)
                if vpc.version != 4:
                    raise ValueError("IPv4 required")
                subnets = [
                    ipaddress.ip_network(str(value["public_subnet_cidr"]), strict=True),
                    ipaddress.ip_network(str(value["appliance_subnet_cidr"]), strict=True),
                ] + [
                    ipaddress.ip_network(cidr, strict=True)
                    for field in role_maps.values()
                    for cidr in field.values()
                ]
            except ValueError as error:
                raise LifecycleError(f"sites.{site} contains an invalid canonical IPv4 network") from error
            if any(network.version != 4 or not network.subnet_of(vpc) for network in subnets):
                raise LifecycleError(f"every sites.{site} subnet must be contained by its VPC")
            for index, network in enumerate(subnets):
                if any(network.overlaps(other) for other in subnets[index + 1 :]):
                    raise LifecycleError(f"sites.{site} subnet role CIDRs must not overlap")
            returns = [str(cidr) for cidr in value["gwlb_return_cidrs"]] if isinstance(value["gwlb_return_cidrs"], list) else []
            deliveries = [str(cidr) for cidr in value["local_delivery_cidrs"]] if isinstance(value["local_delivery_cidrs"], list) else []
            workload_values = set(role_maps["workload_subnet_cidrs"].values())
            if (
                not returns
                or not deliveries
                or len(set(returns)) != len(returns)
                or len(set(deliveries)) != len(deliveries)
                or set(returns).intersection(deliveries)
                or set(returns + deliveries) != workload_values
            ):
                raise LifecycleError(f"sites.{site} lane roles must be a non-empty disjoint partition of workload CIDRs")
            normalized_sites[site] = {
                "region": region,
                "ami_id": str(value["ami_id"]),
                "ssm_kms_key_arn": str(value["ssm_kms_key_arn"]),
                "azs": {str(key): str(zone) for key, zone in azs.items()},
                "appliance_az_key": appliance_key,
                "vpc_cidr": str(vpc),
                "public_subnet_cidr": str(value["public_subnet_cidr"]),
                "appliance_subnet_cidr": str(value["appliance_subnet_cidr"]),
                **role_maps,
                "gwlb_return_cidrs": returns,
                "local_delivery_cidrs": deliveries,
            }
            site_networks[site] = vpc
        sites = normalized_sites
        if sites["west"]["region"] == sites["east"]["region"]:
            raise LifecycleError("west and east regions must be distinct")
        if site_networks["west"].overlaps(site_networks["east"]):
            raise LifecycleError("west and east VPC CIDRs must not overlap")
        for key in ("name", "tag", "tag_owners"):
            if key not in tailnet:
                raise LifecycleError(f"tailnet.{key} is required")
        if "lane_cidrs" in tailnet:
            raise LifecycleError("tailnet.lane_cidrs is prohibited; site workload/lane roles are the only CIDR source")
        if not str(tailnet.get("name", "")):
            raise LifecycleError("tailnet.name is required")
        tailnet_keys = {
            "name",
            "tag",
            "tag_owners",
            "snat_subnet_routes",
            "auth_key_expiry_seconds",
            "oauth_client_id_env",
            "oauth_client_secret_env",
        }
        if set(tailnet) - tailnet_keys:
            raise LifecycleError(f"tailnet has unsupported fields: {sorted(set(tailnet) - tailnet_keys)}")
        if tailnet.get("snat_subnet_routes") is not False:
            raise LifecycleError("tailnet.snat_subnet_routes must be false")
        if not re.fullmatch(r"tag:[A-Za-z0-9-]+", str(tailnet.get("tag", ""))):
            raise LifecycleError("tailnet.tag must be a single tag value")
        try:
            auth_expiry = int(tailnet.get("auth_key_expiry_seconds", 3600))
        except (TypeError, ValueError) as error:
            raise LifecycleError("tailnet.auth_key_expiry_seconds must be an integer") from error
        if auth_expiry < 300 or auth_expiry > 3600:
            raise LifecycleError("tailnet.auth_key_expiry_seconds must be between 300 and 3600")
        owners = tailnet.get("tag_owners")
        if not isinstance(owners, list) or not owners or not all(isinstance(value, str) and value for value in owners):
            raise LifecycleError("tailnet.tag_owners must be a non-empty string list")
        tailnet = {
            "name": str(tailnet["name"]),
            "tag": str(tailnet["tag"]),
            "tag_owners": [str(value) for value in owners],
            "snat_subnet_routes": False,
            "auth_key_expiry_seconds": auth_expiry,
            "oauth_client_id_env": str(tailnet.get("oauth_client_id_env", "TS_OAUTH_CLIENT_ID")),
            "oauth_client_secret_env": str(tailnet.get("oauth_client_secret_env", "TS_OAUTH_CLIENT_SECRET")),
        }
        if tailnet["oauth_client_id_env"] == tailnet["oauth_client_secret_env"] or not all(
            re.fullmatch(r"[A-Z_][A-Z0-9_]*", tailnet[key])
            for key in ("oauth_client_id_env", "oauth_client_secret_env")
        ):
            raise LifecycleError("Tailnet OAuth environment variable names must be distinct shell identifiers")
        artifact_value = raw.get("artifact_manifest")
        if not isinstance(artifact_value, str) or not artifact_value:
            raise LifecycleError("artifact_manifest is required")
        artifact_manifest = pathlib.Path(artifact_value).expanduser()
        if not artifact_manifest.is_absolute():
            artifact_manifest = path.parent / artifact_manifest
        artifact_manifest = artifact_manifest.resolve()

        for key in ("instance_type", "test_instance_type"):
            if not isinstance(raw.get(key), str) or not raw[key]:
                raise LifecycleError(f"{key} is required")
        if raw.get("tailscale_version", TAILSCALE_VERSION) != TAILSCALE_VERSION:
            raise LifecycleError(f"tailscale_version must be the reviewed {TAILSCALE_VERSION}")
        tags = raw.get("tags", {})
        if not isinstance(tags, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in tags.items()):
            raise LifecycleError("tags must be a string map")
        if set(tags).intersection({"EnvelopeRun", "ExpiresAt", "ManagedBy", "Profile"}):
            raise LifecycleError("tags cannot override protected ownership tags")
        envelope = raw.get("envelope", {})
        if not isinstance(envelope, dict):
            raise LifecycleError("envelope must be an object")
        envelope_keys = {
            "routing_mode",
            "tun_name",
            "tailscale_iface",
            "underlay_interface",
            "routing_table_id",
            "routing_rule_priority",
        }
        if set(envelope) - envelope_keys:
            raise LifecycleError(f"envelope has unsupported fields: {sorted(set(envelope) - envelope_keys)}")
        try:
            normalized_envelope = {
                "routing_mode": str(envelope.get("routing_mode", "manage")),
                "tun_name": str(envelope.get("tun_name", "envelope0")),
                "tailscale_iface": str(envelope.get("tailscale_iface", "tailscale0")),
                "underlay_interface": str(envelope.get("underlay_interface", "ens5")),
                "routing_table_id": int(envelope.get("routing_table_id", 100)),
                "routing_rule_priority": int(envelope.get("routing_rule_priority", 100)),
            }
        except (TypeError, ValueError) as error:
            raise LifecycleError("envelope routing table and priority must be integers") from error
        if normalized_envelope["routing_mode"] not in {"off", "verify", "manage"}:
            raise LifecycleError("envelope.routing_mode is invalid")
        if normalized_envelope["tun_name"] == normalized_envelope["tailscale_iface"]:
            raise LifecycleError("Envelope and Tailscale interface names must differ")
        if not 1 <= normalized_envelope["routing_table_id"] <= 252 or normalized_envelope["routing_table_id"] == 52:
            raise LifecycleError("envelope.routing_table_id must be 1-252 except 52")
        if not 1 <= normalized_envelope["routing_rule_priority"] <= 32765:
            raise LifecycleError("envelope.routing_rule_priority must be 1-32765")
        cost = raw.get("cost", {})
        if not isinstance(cost, dict):
            raise LifecycleError("cost must be an object")
        cost_keys = {"estimated_fixed_hourly_usd", "approved_max_fixed_hourly_usd"}
        if set(cost) - cost_keys:
            raise LifecycleError(f"cost has unsupported fields: {sorted(set(cost) - cost_keys)}")
        try:
            estimated = float(cost.get("estimated_fixed_hourly_usd", 1.50))
            approved = float(cost.get("approved_max_fixed_hourly_usd", 2.00))
            root_size = int(raw.get("ebs_root_volume_size", 20))
        except (TypeError, ValueError) as error:
            raise LifecycleError("cost and root-volume values must be numeric") from error
        if estimated <= 0 or approved <= 0 or estimated > approved:
            raise LifecycleError("cost estimate must be positive and within the approved ceiling")
        if not 8 <= root_size <= 100:
            raise LifecycleError("ebs_root_volume_size must be 8-100")
        normalized_raw = {
            "instance_type": str(raw["instance_type"]),
            "test_instance_type": str(raw["test_instance_type"]),
            "ebs_root_volume_size": root_size,
            "tags": {str(key): str(value) for key, value in tags.items()},
            "tailscale_version": TAILSCALE_VERSION,
            "envelope": normalized_envelope,
            "cost": {
                "estimated_fixed_hourly_usd": estimated,
                "approved_max_fixed_hourly_usd": approved,
            },
        }
        return cls(path, normalized_raw, run_id, expires_at, backend, sites, tailnet, architecture, artifact_manifest)

    @property
    def manifest_key(self) -> str:
        return f"runs/{self.run_id}/manifest.json"

    @property
    def lock_key(self) -> str:
        return self.backend["state_key"] + ".tflock"

    @property
    def oauth_environment_names(self) -> tuple[str, str]:
        return (self.tailnet["oauth_client_id_env"], self.tailnet["oauth_client_secret_env"])

    @property
    def lane_cidrs(self) -> dict[str, list[str]]:
        return {
            site: self.sites[site]["gwlb_return_cidrs"] + self.sites[site]["local_delivery_cidrs"]
            for site in ("west", "east")
        }

    @property
    def config_identity(self) -> str:
        payload = {
            "run_id": self.run_id,
            "expires_at": self.expires_at,
            "backend": self.backend,
            "sites": self.sites,
            "tailnet": self.tailnet,
            "architecture": self.architecture,
            "runtime": self.raw,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_artifact(config: RunConfig) -> dict[str, Any]:
    try:
        manifest = json.loads(config.artifact_manifest.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise LifecycleError(f"cannot read artifact manifest: {error}") from error
    if manifest.get("schema") != 1 or not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("revision", ""))):
        raise LifecycleError("artifact manifest schema or source revision is invalid")
    if manifest.get("source_dirty") is not False:
        raise LifecycleError("protected deployment refuses an artifact built from a dirty worktree")
    matches = [entry for entry in manifest.get("artifacts", []) if entry.get("architecture") == config.architecture]
    if len(matches) != 1:
        raise LifecycleError("artifact manifest must contain exactly one selected architecture")
    entry = matches[0]
    if entry.get("ec2_architecture") != ARCHITECTURES[config.architecture]:
        raise LifecycleError("artifact manifest has an invalid Go-to-EC2 architecture mapping")
    artifact_file = pathlib.Path(str(entry.get("file", "")))
    if artifact_file.is_absolute() or ".." in artifact_file.parts or artifact_file.name != str(artifact_file):
        raise LifecycleError("artifact file must be one relative basename beside its manifest")
    path = (config.artifact_manifest.parent / artifact_file).resolve()
    if path.parent != config.artifact_manifest.parent.resolve():
        raise LifecycleError("artifact path escapes its reviewed manifest directory")
    try:
        inspected = inspect_artifact(
            path,
            expected_architecture=config.architecture,
            expected_sha256=str(entry.get("sha256", "")),
            expected_revision=str(manifest["revision"]),
            expected_modified=False,
            expected_go_version=str(manifest.get("go_version", "")),
            expected_version=str(manifest.get("version", "")),
            excluded_environment=config.oauth_environment_names,
        )
    except (OSError, ValueError) as error:
        raise LifecycleError(f"artifact binary provenance validation failed: {error}") from error
    expected_metadata = {
        "goos": "linux",
        "goarch": config.architecture,
        "go_version": manifest.get("go_version"),
        "vcs_revision": manifest["revision"],
        "vcs_modified": False,
        "version": manifest.get("version"),
    }
    if any(entry.get(key) != value for key, value in expected_metadata.items()):
        raise LifecycleError("artifact entry provenance differs from its reviewed manifest/build metadata")
    return {
        **entry,
        "path": str(path),
        "revision": manifest["revision"],
        "version": manifest["version"],
        "manifest_path": str(config.artifact_manifest),
        "manifest_sha256": hashlib.sha256(config.artifact_manifest.read_bytes()).hexdigest(),
        "inspected": inspected,
    }


def exact_object_versions(aws: AwsCLI, *, bucket: str, key: str, region: str) -> list[dict[str, str]]:
    response = aws.json(["s3api", "list-object-versions", "--bucket", bucket, "--prefix", key], region=region)
    result: list[dict[str, str]] = []
    for collection, kind in (("Versions", "version"), ("DeleteMarkers", "delete-marker")):
        for item in response.get(collection, []):
            if isinstance(item, dict) and item.get("Key") == key and item.get("VersionId"):
                result.append({"version_id": str(item["VersionId"]), "kind": kind})
    return result


def policy_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def statement_principals(statement: dict[str, Any]) -> list[str]:
    principal = statement.get("Principal")
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, dict):
        return policy_values(principal.get("AWS"))
    return []


def policy_allows(policy: dict[str, Any], principal: str, action: str, resource: str) -> bool:
    for statement in policy.get("Statement", []):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        if principal not in statement_principals(statement):
            continue
        actions = policy_values(statement.get("Action"))
        resources = policy_values(statement.get("Resource"))
        if any(fnmatch.fnmatchcase(action, pattern) for pattern in actions) and any(
            fnmatch.fnmatchcase(resource, pattern) for pattern in resources
        ):
            return True
    return False


BACKEND_BUCKET_ACTIONS = (
    "s3:ListBucket",
    "s3:ListBucketVersions",
    "s3:GetBucketLocation",
    "s3:GetBucketVersioning",
    "s3:GetEncryptionConfiguration",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketPolicy",
)
BACKEND_KMS_ACTIONS = (
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:GenerateDataKey",
    "kms:DescribeKey",
    "kms:GetKeyPolicy",
)


class BackendValidator:
    def __init__(self, aws: AwsCLI):
        self.aws = aws

    def validate(self, config: RunConfig, *, require_empty: bool) -> None:
        bucket, region, kms_key = (
            config.backend["bucket"],
            config.backend["region"],
            config.backend["kms_key_arn"],
        )
        self.aws.json(["s3api", "head-bucket", "--bucket", bucket], region=region)
        location = self.aws.json(["s3api", "get-bucket-location", "--bucket", bucket], region=region)
        actual_region = location.get("LocationConstraint") or "us-east-1"
        if actual_region != region:
            raise LifecycleError("backend bucket region differs from the configured region")
        versioning = self.aws.json(["s3api", "get-bucket-versioning", "--bucket", bucket], region=region)
        if versioning.get("Status") != "Enabled":
            raise LifecycleError("backend bucket versioning must be Enabled")
        encryption = self.aws.json(["s3api", "get-bucket-encryption", "--bucket", bucket], region=region)
        rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if not any(
            rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") == "aws:kms"
            and rule.get("ApplyServerSideEncryptionByDefault", {}).get("KMSMasterKeyID") == kms_key
            for rule in rules
            if isinstance(rule, dict)
        ):
            raise LifecycleError("backend bucket must default to the exact operator-owned KMS key")
        public = self.aws.json(["s3api", "get-public-access-block", "--bucket", bucket], region=region)
        block = public.get("PublicAccessBlockConfiguration", {})
        required = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
        if not all(block.get(key) is True for key in required):
            raise LifecycleError("backend bucket public access block must be fully enabled")
        policy_status = self.aws.json(["s3api", "get-bucket-policy-status", "--bucket", bucket], region=region)
        if policy_status.get("PolicyStatus", {}).get("IsPublic") is not False:
            raise LifecycleError("backend bucket policy must be present and non-public")
        policy_response = self.aws.json(["s3api", "get-bucket-policy", "--bucket", bucket], region=region)
        try:
            bucket_policy = json.loads(str(policy_response.get("Policy", "")))
        except json.JSONDecodeError as error:
            raise LifecycleError("backend bucket policy is not valid JSON") from error
        statements = bucket_policy.get("Statement", []) if isinstance(bucket_policy, dict) else []
        secure_transport_deny = any(
            isinstance(statement, dict)
            and statement.get("Effect") == "Deny"
            and "s3:*" in policy_values(statement.get("Action"))
            and "*" in statement_principals(statement)
            and "false" in [str(value).lower() for value in policy_values(statement.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport"))]
            for statement in statements
        )
        if not secure_transport_deny:
            raise LifecycleError("backend bucket policy must deny insecure transport")
        bucket_arn = f"arn:aws:s3:::{bucket}"
        object_actions = {
            f"{bucket_arn}/{config.backend['state_key']}": (
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObjectVersion",
            ),
            f"{bucket_arn}/{config.lock_key}": (
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:DeleteObjectVersion",
            ),
            f"{bucket_arn}/{config.manifest_key}": (
                "s3:GetObject",
                "s3:PutObject",
                "s3:PutObjectTagging",
                "s3:DeleteObjectVersion",
            ),
        }
        for principal in config.backend["operator_principal_arns"]:
            for action in BACKEND_BUCKET_ACTIONS:
                if not policy_allows(bucket_policy, principal, action, bucket_arn):
                    raise LifecycleError(f"backend policy omits {action} on the backend bucket for {principal}")
            for object_arn, actions in object_actions.items():
                for action in actions:
                    if not policy_allows(bucket_policy, principal, action, object_arn):
                        raise LifecycleError(f"backend policy omits {action} for a run-owned object")

        key = self.aws.json(["kms", "describe-key", "--key-id", kms_key], region=region).get("KeyMetadata", {})
        if (
            key.get("Arn") != kms_key
            or key.get("Enabled") is not True
            or key.get("KeyUsage") != "ENCRYPT_DECRYPT"
            or key.get("KeySpec") != "SYMMETRIC_DEFAULT"
            or key.get("KeyManager") != "CUSTOMER"
        ):
            raise LifecycleError("backend KMS key must be the exact enabled customer symmetric encryption key")
        key_policy_response = self.aws.json(
            ["kms", "get-key-policy", "--key-id", kms_key, "--policy-name", "default"], region=region
        )
        try:
            key_policy = json.loads(str(key_policy_response.get("Policy", "")))
        except json.JSONDecodeError as error:
            raise LifecycleError("backend KMS key policy is not valid JSON") from error
        for principal in config.backend["operator_principal_arns"]:
            for action in BACKEND_KMS_ACTIONS:
                if not policy_allows(key_policy, principal, action, "*") and not policy_allows(
                    key_policy, principal, action, kms_key
                ):
                    raise LifecycleError(f"backend KMS key policy omits {action} for a protected operator")
        if require_empty:
            for key in (config.backend["state_key"], config.lock_key, config.manifest_key):
                if exact_object_versions(self.aws, bucket=bucket, key=key, region=region):
                    raise LifecycleError(f"run-owned backend key has a historical version or delete marker: {key}")


def validate_aws_metadata(config: RunConfig, aws: AwsCLI) -> None:
    expected = ARCHITECTURES[config.architecture]
    appliance_type = str(config.raw.get("instance_type", ""))
    test_type = str(config.raw.get("test_instance_type", ""))
    if not appliance_type or not test_type:
        raise LifecycleError("instance_type and test_instance_type are required")
    for site in ("west", "east"):
        region = config.sites[site]["region"]
        image_id = config.sites[site]["ami_id"]
        response = aws.json(["ec2", "describe-images", "--image-ids", image_id], region=region)
        images = response.get("Images", [])
        if len(images) != 1:
            raise LifecycleError(f"{site} AMI metadata did not return exactly one image")
        image = images[0]
        if (
            image.get("ImageId") != image_id
            or image.get("Architecture") != expected
            or image.get("State") != "available"
            or image.get("RootDeviceType") != "ebs"
            or image.get("VirtualizationType") != "hvm"
            or not str(image.get("Name", "")).startswith("al2023-ami-")
        ):
            raise LifecycleError(f"{site} AMI is not a compatible explicit AL2023 {expected} image")
        types = aws.json(
            ["ec2", "describe-instance-types", "--instance-types", appliance_type, test_type], region=region
        ).get("InstanceTypes", [])
        by_name = {value.get("InstanceType"): value for value in types if isinstance(value, dict)}
        for selected in (appliance_type, test_type):
            supported = by_name.get(selected, {}).get("ProcessorInfo", {}).get("SupportedArchitectures", [])
            if expected not in supported:
                raise LifecycleError(f"{site} instance type {selected} does not support {expected}")


class ManifestStore:
    def __init__(self, config: RunConfig, aws: AwsCLI, run_dir: pathlib.Path):
        self.config = config
        self.aws = aws
        self.run_dir = run_dir.expanduser().resolve()
        self.path = self.run_dir / "manifest.json"
        self.remote_etag: str | None = None

    def write(
        self,
        manifest: dict[str, Any],
        *,
        upload: bool = True,
        if_match: str | None = None,
        if_none_match: bool = False,
    ) -> None:
        self.run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        effective_if_match = if_match if if_match is not None else self.remote_etag
        fd, temporary = tempfile.mkstemp(prefix="manifest.", dir=self.run_dir)
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(manifest, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            if upload and (effective_if_match is not None or if_none_match):
                self._upload(pathlib.Path(temporary), if_match=effective_if_match, if_none_match=if_none_match)
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        if upload and effective_if_match is None and not if_none_match:
            self._upload(self.path)

    def _upload(self, path: pathlib.Path, *, if_match: str | None = None, if_none_match: bool = False) -> None:
        tagging = urllib.parse.urlencode({"EnvelopeRun": self.config.run_id, "ExpiresAt": self.config.expires_at})
        args = [
            "s3api",
            "put-object",
            "--bucket",
            self.config.backend["bucket"],
            "--key",
            self.config.manifest_key,
            "--body",
            str(path),
            "--server-side-encryption",
            "aws:kms",
            "--ssekms-key-id",
            self.config.backend["kms_key_arn"],
            "--tagging",
            tagging,
        ]
        if if_match is not None:
            args.extend(["--if-match", if_match])
        if if_none_match:
            args.extend(["--if-none-match", "*"])
        response = self.aws.json(args, region=self.config.backend["region"])
        etag = response.get("ETag")
        self.remote_etag = str(etag) if isinstance(etag, str) and etag else None
        if (if_match is not None or if_none_match) and self.remote_etag is None:
            raise LifecycleError("conditional durable manifest write returned no ETag")

    def load_local(self) -> dict[str, Any]:
        try:
            manifest = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise LifecycleError(f"cannot load protected cleanup manifest: {error}") from error
        validate_manifest(manifest, self.config)
        return manifest

    def recover(self) -> dict[str, Any]:
        self.run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        response = self.aws.json(
            [
                "s3api",
                "get-object",
                "--bucket",
                self.config.backend["bucket"],
                "--key",
                self.config.manifest_key,
                str(self.path),
            ],
            region=self.config.backend["region"],
        )
        etag = response.get("ETag")
        self.remote_etag = str(etag) if isinstance(etag, str) and etag else None
        os.chmod(self.path, 0o600)
        return self.load_local()


def validate_manifest(manifest: dict[str, Any], config: RunConfig) -> None:
    if manifest.get("schema") != SCHEMA or manifest.get("run_id") != config.run_id:
        raise LifecycleError("cleanup manifest identity does not match the requested run")
    if manifest.get("expires_at") != config.expires_at or manifest.get("configuration_sha256") != config.config_identity:
        raise LifecycleError("cleanup manifest configuration identity does not match the requested run")
    backend = manifest.get("backend", {})
    if (
        backend.get("bucket") != config.backend["bucket"]
        or backend.get("region") != config.backend["region"]
        or backend.get("kms_key_arn") != config.backend["kms_key_arn"]
        or backend.get("state_key") != config.backend["state_key"]
        or backend.get("lock_key") != config.lock_key
        or backend.get("manifest_key") != config.manifest_key
    ):
        raise LifecycleError("cleanup manifest backend ownership does not match run configuration")
    variables = manifest.get("terraform_variables")
    if not isinstance(variables, dict) or variables.get("name") != config.run_id or variables.get("expires_at") != config.expires_at:
        raise LifecycleError("cleanup manifest omits its complete Terraform destroy identity")
    account_id = str(manifest.get("aws_account_id", ""))
    if not re.fullmatch(r"[0-9]{12}", account_id):
        raise LifecycleError("cleanup manifest AWS account identity is invalid")
    expected_parameters = intended_ssm_parameters(config, account_id)
    actual_parameters = manifest.get("ssm_parameters")
    if not isinstance(actual_parameters, list) or len(actual_parameters) != 2:
        raise LifecycleError("cleanup manifest must retain both intended regional SSM parameters")
    for expected, actual in zip(expected_parameters, actual_parameters, strict=True):
        if not isinstance(actual, dict) or any(actual.get(key) != expected[key] for key in ("site", "region", "name", "arn", "kms_key_arn")):
            raise LifecycleError("cleanup manifest SSM intent differs from the requested run identity")
    tailnet = manifest.get("tailnet", {})
    if (
        tailnet.get("name") != config.tailnet["name"]
        or tailnet.get("tag") != config.tailnet["tag"]
        or not isinstance(tailnet.get("device_ids"), dict)
    ):
        raise LifecycleError("cleanup manifest Tailnet identity differs from the requested run")
    source = manifest.get("terraform_source")
    if source is not None:
        if not isinstance(source, dict):
            raise LifecycleError("cleanup manifest Terraform source identity is invalid")
        terraform_source_identity(source)
        files = source.get("files")
        if files is not None and (
            not isinstance(files, dict)
            or not files
            or any(not isinstance(path, str) or not isinstance(value, str) for path, value in files.items())
        ):
            raise LifecycleError("cleanup manifest Terraform source bundle is invalid")
    serialized = json.dumps(manifest)
    if "tskey-" in serialized.lower() or "oauth_client_secret" in serialized.lower():
        raise LifecycleError("cleanup manifest contains prohibited secret material")


def caller_account_id(aws: AwsCLI) -> str:
    identity = aws.json(["sts", "get-caller-identity"])
    account = str(identity.get("Account", ""))
    if not re.fullmatch(r"[0-9]{12}", account):
        raise LifecycleError("AWS caller identity omitted a 12-digit account ID")
    return account


def intended_ssm_parameters(config: RunConfig, account_id: str) -> list[dict[str, Any]]:
    result = []
    for site in ("west", "east"):
        partition = str(config.sites[site]["ssm_kms_key_arn"]).split(":", 2)[1]
        name = f"/{config.run_id}/tailscale-auth"
        result.append(
            {
                "site": site,
                "region": config.sites[site]["region"],
                "name": name,
                "arn": f"arn:{partition}:ssm:{config.sites[site]['region']}:{account_id}:parameter/{config.run_id}/tailscale-auth",
                "kms_key_arn": config.sites[site]["ssm_kms_key_arn"],
                "created": False,
            }
        )
    return result


def terraform_variables(
    config: RunConfig, artifact: dict[str, Any], parameters: list[dict[str, Any]]
) -> dict[str, Any]:
    by_site = {str(parameter["site"]): parameter for parameter in parameters}
    west, east = config.sites["west"], config.sites["east"]
    envelope = config.raw["envelope"]
    return {
        "name": config.run_id,
        "expires_at": config.expires_at,
        "tags": config.raw["tags"],
        "west_region": west["region"],
        "east_region": east["region"],
        "west_azs": west["azs"],
        "east_azs": east["azs"],
        "west_appliance_az_key": west["appliance_az_key"],
        "east_appliance_az_key": east["appliance_az_key"],
        "west_vpc_cidr": west["vpc_cidr"],
        "east_vpc_cidr": east["vpc_cidr"],
        "west_public_subnet_cidr": west["public_subnet_cidr"],
        "east_public_subnet_cidr": east["public_subnet_cidr"],
        "west_appliance_subnet_cidr": west["appliance_subnet_cidr"],
        "east_appliance_subnet_cidr": east["appliance_subnet_cidr"],
        "west_workload_subnet_cidrs": west["workload_subnet_cidrs"],
        "east_workload_subnet_cidrs": east["workload_subnet_cidrs"],
        "west_gwlbe_subnet_cidrs": west["gwlbe_subnet_cidrs"],
        "east_gwlbe_subnet_cidrs": east["gwlbe_subnet_cidrs"],
        "west_gwlb_subnet_cidrs": west["gwlb_subnet_cidrs"],
        "east_gwlb_subnet_cidrs": east["gwlb_subnet_cidrs"],
        "architecture": config.architecture,
        "west_ami_id": west["ami_id"],
        "east_ami_id": east["ami_id"],
        "instance_type": config.raw["instance_type"],
        "test_instance_type": config.raw["test_instance_type"],
        "ebs_root_volume_size": config.raw["ebs_root_volume_size"],
        "artifact_path": str(pathlib.Path(str(artifact["path"])).resolve()),
        "artifact_sha256": artifact["sha256"],
        "artifact_revision": artifact["revision"],
        "artifact_version": artifact["version"],
        "west_tailscale_secret_arn": by_site["west"]["arn"],
        "east_tailscale_secret_arn": by_site["east"]["arn"],
        "west_tailscale_kms_key_arn": by_site["west"]["kms_key_arn"],
        "east_tailscale_kms_key_arn": by_site["east"]["kms_key_arn"],
        "tailscale_tag": config.tailnet["tag"],
        "tailscale_version": TAILSCALE_VERSION,
        "envelope_routing_mode": envelope["routing_mode"],
        "envelope_tun_name": envelope["tun_name"],
        "envelope_tailscale_iface": envelope["tailscale_iface"],
        "envelope_underlay_interface": envelope["underlay_interface"],
        "envelope_gwlb_return_cidrs": {
            site: config.sites[site]["gwlb_return_cidrs"] for site in ("west", "east")
        },
        "envelope_local_delivery_cidrs": {
            site: config.sites[site]["local_delivery_cidrs"] for site in ("west", "east")
        },
        "envelope_remote_tailnet_cidrs": {
            "west": [east["workload_subnet_cidrs"][key] for key in sorted(east["workload_subnet_cidrs"])],
            "east": [west["workload_subnet_cidrs"][key] for key in sorted(west["workload_subnet_cidrs"])],
        },
        "envelope_routing_table_id": envelope["routing_table_id"],
        "envelope_routing_rule_priority": envelope["routing_rule_priority"],
        "appliance_target_count": 1,
        "estimated_fixed_hourly_usd": config.raw["cost"]["estimated_fixed_hourly_usd"],
        "approved_max_fixed_hourly_usd": config.raw["cost"]["approved_max_fixed_hourly_usd"],
    }


def new_manifest(config: RunConfig, artifact: dict[str, Any], account_id: str) -> dict[str, Any]:
    parameters = intended_ssm_parameters(config, account_id)
    artifact_bucket = f"{config.run_id}-{account_id}-{config.sites['west']['region']}-artifact"
    artifact_key = f"artifacts/{artifact['revision']}/envelope-linux-{config.architecture}"
    return {
        "schema": SCHEMA,
        "run_id": config.run_id,
        "expires_at": config.expires_at,
        "configuration_sha256": config.config_identity,
        "aws_account_id": account_id,
        "phase": "preflight_complete",
        "ownership_tag": {"EnvelopeRun": config.run_id},
        "backend": {
            "bucket": config.backend["bucket"],
            "region": config.backend["region"],
            "kms_key_arn": config.backend["kms_key_arn"],
            "state_key": config.backend["state_key"],
            "lock_key": config.lock_key,
            "manifest_key": config.manifest_key,
        },
        "artifact": {
            **{key: artifact[key] for key in ("architecture", "ec2_architecture", "sha256", "revision", "version")},
            "go_version": artifact["go_version"],
            "manifest_sha256": artifact["manifest_sha256"],
            "manifest_path": artifact["manifest_path"],
            "source_path": str(pathlib.Path(str(artifact["path"])).resolve()),
            "object": {"bucket": artifact_bucket, "key": artifact_key, "region": config.sites["west"]["region"]},
        },
        "tailnet": {
            "name": config.tailnet["name"],
            "tag": config.tailnet["tag"],
            "auth_key_description": f"Envelope acceptance {config.run_id}",
            "auth_key_id": None,
            "key_generation": 0,
            "pending_revoke_key_ids": [],
            "expected_hostnames": [f"{config.run_id}-west", f"{config.run_id}-east"],
            "nodes_expected": False,
            "device_ids": {},
        },
        "ssm_parameters": parameters,
        "terraform_variables": terraform_variables(config, artifact, parameters),
    }


def put_ssm_parameter(
    aws: AwsCLI,
    *,
    run_dir: pathlib.Path,
    run_id: str,
    expires_at: str,
    site: str,
    region: str,
    kms_key_arn: str,
    secret: str,
    expected_arn: str | None = None,
    overwrite: bool = False,
    mutation_callback: Callable[[], None] | None = None,
) -> dict[str, Any]:
    run_dir = run_dir.expanduser().resolve()
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = f"/{run_id}/tailscale-auth"
    payload = {
        "Name": name,
        "Description": f"Ephemeral Envelope acceptance bootstrap for {run_id}",
        "Value": secret,
        "Type": "SecureString",
        "KeyId": kms_key_arn,
        "Overwrite": overwrite,
        "Tier": "Standard",
        "DataType": "text",
    }
    if not overwrite:
        payload["Tags"] = [
            {"Key": "EnvelopeRun", "Value": run_id},
            {"Key": "ExpiresAt", "Value": expires_at},
            {"Key": "Site", "Value": site},
        ]
    fd, payload_path_value = tempfile.mkstemp(prefix=f"ssm-{site}.", suffix=".json", dir=run_dir)
    payload_path = pathlib.Path(payload_path_value)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(payload, stream, separators=(",", ":"))
        os.chmod(payload_path, 0o600)
        aws.json(
            ["ssm", "put-parameter", "--cli-input-json", f"file://{payload_path}"],
            region=region,
        )
        if mutation_callback is not None:
            mutation_callback()
    finally:
        payload["Value"] = ""
        try:
            payload_path.unlink()
        except FileNotFoundError:
            pass
    described = aws.json(["ssm", "describe-parameters", "--parameter-filters", f"Key=Name,Values={name}"], region=region)
    parameters = described.get("Parameters", [])
    if len(parameters) != 1 or not parameters[0].get("ARN"):
        raise LifecycleError(f"created {site} SSM parameter could not be identified")
    arn = str(parameters[0]["ARN"])
    if expected_arn is not None and arn != expected_arn:
        raise LifecycleError(f"created {site} SSM parameter ARN differs from its durable intent")
    return {
        "site": site,
        "region": region,
        "name": name,
        "arn": arn,
        "kms_key_arn": kms_key_arn,
        "created": True,
    }


def delete_ssm_parameter(aws: AwsCLI, parameter: dict[str, Any]) -> None:
    try:
        aws.json(["ssm", "delete-parameter", "--name", parameter["name"]], region=parameter["region"])
    except CommandError as error:
        if "ParameterNotFound" not in error.raw_stderr:
            raise


def get_ssm_parameter_value(aws: AwsCLI, parameter: dict[str, Any]) -> str:
    response = aws.json(
        ["ssm", "get-parameter", "--name", str(parameter["name"]), "--with-decryption"],
        region=str(parameter["region"]),
    )
    value = response.get("Parameter", {}).get("Value")
    if not isinstance(value, str) or not value:
        raise LifecycleError(f"{parameter['site']} SSM parameter returned no secret value")
    return value


def build_tailscale(config: RunConfig, transport: HTTPTransport | None = None) -> TailscaleAPI:
    client_id_env = str(config.tailnet.get("oauth_client_id_env", "TS_OAUTH_CLIENT_ID"))
    secret_env = str(config.tailnet.get("oauth_client_secret_env", "TS_OAUTH_CLIENT_SECRET"))
    return TailscaleAPI(
        str(config.tailnet["name"]),
        os.environ.get(client_id_env, ""),
        os.environ.get(secret_env, ""),
        transport or UrllibTransport(),
    )


def tailnet_preflight(config: RunConfig, tailscale: TailscaleAPI) -> None:
    policy = parse_hujson(tailscale.policy_text())
    lane_cidrs = config.lane_cidrs
    advertised = lane_cidrs["west"] + lane_cidrs["east"]
    validate_tailnet_policy(
        policy,
        tag=str(config.tailnet["tag"]),
        tag_owners=[str(value) for value in config.tailnet["tag_owners"]],
        advertised_routes=advertised,
        lane_cidrs=lane_cidrs,
        snat_subnet_routes=bool(config.tailnet["snat_subnet_routes"]),
    )
    tailscale.list_devices()


def write_runtime_variables(
    config: RunConfig, store: ManifestStore, manifest: dict[str, Any], artifact: dict[str, Any]
) -> pathlib.Path:
    values = terraform_variables(config, artifact, manifest["ssm_parameters"])
    durable = manifest.get("terraform_variables")
    if not isinstance(durable, dict):
        raise LifecycleError("durable manifest has no Terraform variable set")
    comparable = dict(values)
    comparable["artifact_path"] = durable.get("artifact_path")
    if comparable != durable:
        raise LifecycleError("validated run config differs from the durable Terraform variable set")
    values["artifact_path"] = str(pathlib.Path(str(artifact["path"])).resolve())
    path = store.run_dir / "runtime.tfvars.json"
    path.write_text(json.dumps(values, sort_keys=True, separators=(",", ":")) + "\n")
    os.chmod(path, 0o600)
    return path


def run_preflight(
    config: RunConfig, aws: AwsCLI, tailscale: TailscaleAPI, *, require_empty: bool = True
) -> tuple[dict[str, Any], str]:
    artifact = validate_artifact(config)
    BackendValidator(aws).validate(config, require_empty=require_empty)
    validate_aws_metadata(config, aws)
    tailnet_preflight(config, tailscale)
    return artifact, caller_account_id(aws)


def recover_auth_key_ids(tailscale: TailscaleAPI, manifest: dict[str, Any]) -> list[str]:
    tailnet = manifest["tailnet"]
    rotation = tailnet.get("rotation", {}) if isinstance(tailnet.get("rotation"), dict) else {}
    identifiers = {
        str(value)
        for value in [
            tailnet.get("auth_key_id"),
            rotation.get("new_key_id"),
            *tailnet.get("pending_revoke_key_ids", []),
        ]
        if value
    }
    descriptions: list[str] = []
    if tailnet.get("auth_key_id") is None and manifest.get("phase") not in {"preflight_complete"}:
        descriptions.append(str(tailnet["auth_key_description"]))
    if rotation and rotation.get("new_key_id") is None and rotation.get("description"):
        descriptions.append(str(rotation["description"]))
    if descriptions:
        keys = tailscale.list_auth_keys()
        for description in descriptions:
            matches = [str(key.get("id")) for key in keys if key.get("description") == description and key.get("id")]
            if len(matches) > 1:
                raise LifecycleError("multiple Tailscale auth keys match an exact durable run description")
            identifiers.update(matches)
    return sorted(identifiers)


@serialized_run_operation
def prepare(config: RunConfig, aws: AwsCLI, tailscale: TailscaleAPI, run_dir: pathlib.Path) -> dict[str, Any]:
    artifact, account_id = run_preflight(config, aws, tailscale)
    store = ManifestStore(config, aws, run_dir)
    manifest = new_manifest(config, artifact, account_id)
    manifest["prepare_started_at"] = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    store.write(manifest, if_none_match=True)
    key_material: str | None = None
    try:
        manifest["phase"] = "auth_key_create_started"
        store.write(manifest)
        key_id, key_material = tailscale.create_auth_key(
            str(config.tailnet["tag"]),
            str(manifest["tailnet"]["auth_key_description"]),
            int(config.tailnet["auth_key_expiry_seconds"]),
        )
        manifest["tailnet"]["auth_key_id"] = key_id
        manifest["phase"] = "auth_key_created"
        store.write(manifest)
        for index, site in enumerate(("west", "east")):
            intent = manifest["ssm_parameters"][index]
            manifest["phase"] = f"{site}_secret_create_started"
            store.write(manifest)
            parameter = put_ssm_parameter(
                aws,
                run_dir=store.run_dir,
                run_id=config.run_id,
                expires_at=config.expires_at,
                site=site,
                region=config.sites[site]["region"],
                kms_key_arn=config.sites[site]["ssm_kms_key_arn"],
                secret=key_material,
                expected_arn=str(intent["arn"]),
            )
            manifest["ssm_parameters"][index] = parameter
            manifest["phase"] = f"{site}_secret_created"
            store.write(manifest)
        manifest.pop("prepare_started_at", None)
        manifest["phase"] = "prepared"
        store.write(manifest)
        write_runtime_variables(config, store, manifest, artifact)
        return manifest
    except Exception:
        for parameter in reversed(manifest["ssm_parameters"]):
            try:
                delete_ssm_parameter(aws, parameter)
            except Exception:
                pass
        try:
            key_ids = recover_auth_key_ids(tailscale, manifest)
        except Exception:
            key_ids = [str(manifest["tailnet"]["auth_key_id"])] if manifest["tailnet"].get("auth_key_id") else []
        for key_id in key_ids:
            try:
                tailscale.revoke_auth_key(key_id)
            except Exception:
                pass
        manifest.pop("prepare_started_at", None)
        manifest["phase"] = "prepare_failed_cleanup_attempted"
        store.write(manifest)
        raise
    finally:
        key_material = None


@serialized_run_operation
def rotate_auth_key(
    config: RunConfig, aws: AwsCLI, tailscale: TailscaleAPI, run_dir: pathlib.Path
) -> dict[str, Any]:
    store = ManifestStore(config, aws, run_dir)
    manifest = store.recover()
    if store.remote_etag is None:
        raise LifecycleError("protected key rotation requires the current durable manifest ETag")
    if manifest.get("phase") != "ready":
        raise LifecycleError("protected key rotation requires a fully ready deployment")
    old_ids = recover_auth_key_ids(tailscale, manifest)
    if len(old_ids) != 1 or manifest["tailnet"].get("pending_revoke_key_ids"):
        raise LifecycleError("protected key rotation requires one current key and no pending revocation")
    old_id = old_ids[0]
    old_values: dict[str, str] = {}
    new_material: str | None = None
    new_id: str | None = None
    updated: list[dict[str, Any]] = []
    try:
        for parameter in manifest["ssm_parameters"]:
            old_values[str(parameter["site"])] = get_ssm_parameter_value(aws, parameter)
        generation = int(manifest["tailnet"].get("key_generation", 0)) + 1
        rotation_description = f"{manifest['tailnet']['auth_key_description']} rotation-{generation}"
        in_progress = copy.deepcopy(manifest)
        in_progress["tailnet"]["rotation"] = {
            "description": rotation_description,
            "new_key_id": None,
            "updated_sites": [],
        }
        in_progress["key_rotation_started_at"] = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        )
        in_progress["phase"] = "key_rotation_create_started"
        store.write(in_progress, if_match=store.remote_etag)
        new_id, new_material = tailscale.create_auth_key(
            str(config.tailnet["tag"]),
            rotation_description,
            int(config.tailnet["auth_key_expiry_seconds"]),
        )
        in_progress["tailnet"]["rotation"]["new_key_id"] = new_id
        in_progress["phase"] = "key_rotation_key_created"
        store.write(in_progress)
        for parameter in manifest["ssm_parameters"]:
            in_progress["phase"] = f"key_rotation_{parameter['site']}_update_started"
            store.write(in_progress)

            def track_mutation(parameter: dict[str, Any] = parameter) -> None:
                updated.append(parameter)
                in_progress["tailnet"]["rotation"]["updated_sites"].append(str(parameter["site"]))
                in_progress["phase"] = f"key_rotation_{parameter['site']}_write_succeeded"
                store.write(in_progress)

            put_ssm_parameter(
                aws,
                run_dir=store.run_dir,
                run_id=config.run_id,
                expires_at=config.expires_at,
                site=str(parameter["site"]),
                region=str(parameter["region"]),
                kms_key_arn=str(parameter["kms_key_arn"]),
                secret=new_material,
                expected_arn=str(parameter["arn"]),
                overwrite=True,
                mutation_callback=track_mutation,
            )
            in_progress["phase"] = f"key_rotation_{parameter['site']}_verified"
            store.write(in_progress)
        candidate = copy.deepcopy(manifest)
        candidate["tailnet"]["auth_key_id"] = new_id
        candidate["tailnet"]["key_generation"] = generation
        candidate["tailnet"]["pending_revoke_key_ids"] = [old_id]
        candidate["tailnet"].pop("rotation", None)
        candidate.pop("key_rotation_started_at", None)
        candidate["phase"] = "key_rotation_parameters_updated"
        store.write(candidate)
    except Exception as error:
        rollback_failures: list[str] = []
        for parameter in reversed(updated):
            try:
                put_ssm_parameter(
                    aws,
                    run_dir=store.run_dir,
                    run_id=config.run_id,
                    expires_at=config.expires_at,
                    site=str(parameter["site"]),
                    region=str(parameter["region"]),
                    kms_key_arn=str(parameter["kms_key_arn"]),
                    secret=old_values[str(parameter["site"])],
                    expected_arn=str(parameter["arn"]),
                    overwrite=True,
                )
            except Exception:
                rollback_failures.append(str(parameter["site"]))
        recovery_ids = [new_id] if new_id else []
        if not recovery_ids and "in_progress" in locals():
            try:
                recovery_ids = [
                    str(key.get("id"))
                    for key in tailscale.list_auth_keys()
                    if key.get("description") == in_progress["tailnet"]["rotation"]["description"] and key.get("id")
                ]
            except Exception:
                rollback_failures.append("rotation-auth-key-discovery")
        for recovery_id in recovery_ids:
            try:
                tailscale.revoke_auth_key(recovery_id)
            except Exception:
                rollback_failures.append("new-auth-key")
        try:
            store.write(manifest)
        except Exception:
            rollback_failures.append("durable-manifest")
        if rollback_failures:
            raise LifecycleError(
                f"key rotation failed and rollback requires operator recovery for {','.join(rollback_failures)}"
            ) from error
        raise
    finally:
        new_material = None
        old_values.clear()

    try:
        tailscale.revoke_auth_key(old_id)
    except Exception:
        candidate["phase"] = "key_rotation_pending_old_key_revoke"
        store.write(candidate)
        raise
    candidate["tailnet"]["pending_revoke_key_ids"] = []
    candidate["phase"] = "key_rotated"
    store.write(candidate)
    return candidate


def backend_config_text(config: RunConfig) -> str:
    values: dict[str, Any] = {
        "bucket": config.backend["bucket"],
        "key": config.backend["state_key"],
        "region": config.backend["region"],
        "encrypt": True,
        "kms_key_id": config.backend["kms_key_arn"],
        "use_lockfile": True,
    }
    lines = []
    for key, value in values.items():
        rendered = "true" if value is True else json.dumps(value)
        lines.append(f"{key} = {rendered}")
    return "\n".join(lines) + "\n"


def child_environment(config: RunConfig, **values: str) -> dict[str, str]:
    env = os.environ.copy()
    for name in config.oauth_environment_names:
        env.pop(name, None)
    env.update(values)
    return env


def terraform_source_digest(terraform_dir: pathlib.Path) -> str:
    terraform_dir = terraform_dir.expanduser().resolve()
    digest = hashlib.sha256()
    paths = sorted(terraform_dir.rglob("*"), key=lambda value: value.relative_to(terraform_dir).as_posix())
    if not paths:
        raise LifecycleError("reviewed Terraform source snapshot is empty")
    for path in paths:
        if path.is_symlink():
            raise LifecycleError("reviewed Terraform source snapshot contains a symlink")
        if not path.is_file():
            continue
        relative = path.relative_to(terraform_dir).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def terraform_source_identity(source: dict[str, Any]) -> dict[str, str]:
    identity = {key: source.get(key) for key in ("revision", "repository_path", "sha256")}
    if (
        not re.fullmatch(r"[0-9a-f]{40}", str(identity["revision"]))
        or not isinstance(identity["repository_path"], str)
        or not identity["repository_path"]
        or not re.fullmatch(r"[0-9a-f]{64}", str(identity["sha256"]))
    ):
        raise LifecycleError("durable Terraform source identity is invalid")
    return {key: str(value) for key, value in identity.items()}


def strip_hcl_comments(source: str) -> str:
    result: list[str] = []
    index = 0
    in_string = False
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if in_string:
            result.append(character)
            if character == "\\" and following:
                result.append(following)
                index += 2
                continue
            if character == '"':
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
            result.append(character)
            index += 1
            continue
        if character == "#" or character == "/" and following == "/":
            while index < len(source) and source[index] != "\n":
                result.append(" ")
                index += 1
            continue
        if character == "/" and following == "*":
            result.extend((" ", " "))
            index += 2
            while index < len(source):
                if source[index] == "*" and index + 1 < len(source) and source[index + 1] == "/":
                    result.extend((" ", " "))
                    index += 2
                    break
                result.append("\n" if source[index] == "\n" else " ")
                index += 1
            else:
                raise LifecycleError("reviewed Terraform source contains an unterminated block comment")
            continue
        result.append(character)
        index += 1
    if in_string:
        raise LifecycleError("reviewed Terraform source contains an unterminated string")
    return "".join(result)


def validate_terraform_source_contract(terraform_dir: pathlib.Path) -> None:
    terraform_dir = terraform_dir.expanduser().resolve()
    prohibited = [
        path
        for path in terraform_dir.iterdir()
        if path.is_file()
        and (
            path.name == "override.tf"
            or path.name.endswith("_override.tf")
            or path.name.endswith(".tf.json")
            or path.name == "terraform.tfvars"
            or path.name.endswith(".auto.tfvars")
        )
    ]
    if prohibited:
        raise LifecycleError("reviewed Terraform source contains an automatic override or variable file")
    expected_blocks = (
        '''resource "aws_lb_target_group_attachment" "west" {
  target_group_arn = aws_lb_target_group.west.arn
  target_id        = aws_instance.envelope_west.id
}''',
        '''resource "aws_lb_target_group_attachment" "east" {
  provider         = aws.east
  target_group_arn = aws_lb_target_group.east.arn
  target_id        = aws_instance.envelope_east.id
}''',
    )
    raw_gwlb = (terraform_dir / "gwlb.tf").read_text()
    if "<<" in raw_gwlb or "\\u" in raw_gwlb or "\\U" in raw_gwlb:
        raise LifecycleError("reviewed GWLB source contains a prohibited heredoc or escaped label")
    gwlb = strip_hcl_comments(raw_gwlb)
    if any(gwlb.count(block) != 1 for block in expected_blocks):
        raise LifecycleError("reviewed Terraform source does not use exact direct regional target attachments")
    for site in ("west", "east"):
        if len(re.findall(rf'resource\s+"aws_lb_target_group_attachment"\s+"{site}"\s*\{{', gwlb)) != 1:
            raise LifecycleError("reviewed Terraform source has an ambiguous regional target attachment")


def terraform_source_record(terraform_dir: pathlib.Path, identity: dict[str, str]) -> dict[str, Any]:
    files = {
        path.relative_to(terraform_dir).as_posix(): base64.b64encode(path.read_bytes()).decode("ascii")
        for path in sorted(terraform_dir.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }
    return {**identity, "files": files}


def materialize_durable_terraform_source(
    source: dict[str, Any], run_dir: pathlib.Path
) -> tuple[pathlib.Path, dict[str, str]]:
    identity = terraform_source_identity(source)
    files = source.get("files")
    if not isinstance(files, dict) or not files:
        raise LifecycleError("durable Terraform source bundle is absent")
    run_dir = run_dir.expanduser().resolve()
    snapshot = (run_dir / "terraform-source").resolve()
    if snapshot.parent != run_dir:
        raise LifecycleError("durable Terraform source snapshot escaped the protected run directory")
    if snapshot.exists():
        shutil.rmtree(snapshot)
    snapshot.mkdir(mode=0o700, parents=True)
    for relative, encoded in sorted(files.items()):
        parsed = pathlib.PurePosixPath(str(relative))
        if (
            not isinstance(relative, str)
            or not isinstance(encoded, str)
            or not relative
            or parsed.is_absolute()
            or ".." in parsed.parts
        ):
            raise LifecycleError("durable Terraform source bundle contains an unsafe entry")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise LifecycleError("durable Terraform source bundle contains invalid base64") from error
        destination = snapshot / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.write_bytes(content)
        os.chmod(destination, 0o600)
    if terraform_source_digest(snapshot) != identity["sha256"]:
        raise LifecycleError("durable Terraform source bundle digest is invalid")
    validate_terraform_source_contract(snapshot)
    return snapshot, identity


def materialize_reviewed_terraform_source(
    runner: CommandRunner,
    terraform_dir: pathlib.Path,
    run_dir: pathlib.Path,
    revision: str,
) -> tuple[pathlib.Path, dict[str, str]]:
    terraform_dir = terraform_dir.expanduser().resolve()
    run_dir = run_dir.expanduser().resolve()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise LifecycleError("reviewed Terraform source requires the exact artifact revision")
    git_env = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    git_env["GIT_NO_REPLACE_OBJECTS"] = "1"
    repository_text = runner.run(
        ["git", "-C", str(terraform_dir), "rev-parse", "--show-toplevel"], env=git_env
    ).strip()
    repository = pathlib.Path(repository_text).expanduser().resolve()
    try:
        source_prefix = terraform_dir.relative_to(repository)
    except ValueError as error:
        raise LifecycleError("Terraform source directory is outside its Git repository") from error
    object_type = runner.run(["git", "-C", str(repository), "cat-file", "-t", revision], env=git_env).strip()
    if object_type != "commit":
        raise LifecycleError("artifact revision is not an exact Git commit")
    listing = runner.run(
        ["git", "-C", str(repository), "ls-tree", "-r", revision, "--", source_prefix.as_posix()], env=git_env
    )
    entries: list[tuple[str, str]] = []
    prefix = source_prefix.as_posix().rstrip("/") + "/"
    for line in listing.splitlines():
        try:
            metadata, tracked_path = line.split("\t", 1)
            mode, object_type, object_id = metadata.split(" ", 2)
        except ValueError as error:
            raise LifecycleError("Git returned an invalid Terraform source tree entry") from error
        if mode != "100644" or object_type != "blob" or not tracked_path.startswith(prefix):
            raise LifecycleError("reviewed Terraform source tree contains an unsupported entry")
        relative = tracked_path.removeprefix(prefix)
        if not relative or pathlib.PurePosixPath(relative).is_absolute() or ".." in pathlib.PurePosixPath(relative).parts:
            raise LifecycleError("reviewed Terraform source tree contains an unsafe path")
        entries.append((relative, object_id))
    if not entries or not any(path.endswith(".tf") for path, _ in entries) or not any(
        path == ".terraform.lock.hcl" for path, _ in entries
    ):
        raise LifecycleError("reviewed Terraform source tree is incomplete")
    snapshot = (run_dir / "terraform-source").resolve()
    if snapshot.parent != run_dir:
        raise LifecycleError("reviewed Terraform source snapshot escaped the protected run directory")
    if snapshot.exists():
        shutil.rmtree(snapshot)
    snapshot.mkdir(mode=0o700, parents=True)
    for relative, object_id in entries:
        destination = snapshot / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.write_text(
            runner.run(["git", "-C", str(repository), "cat-file", "blob", object_id], env=git_env)
        )
        os.chmod(destination, 0o600)
    validate_terraform_source_contract(snapshot)
    identity = {
        "revision": revision,
        "repository_path": source_prefix.as_posix(),
        "sha256": terraform_source_digest(snapshot),
    }
    return snapshot, identity


@serialized_run_operation
def terraform_init(config: RunConfig, aws: AwsCLI, runner: CommandRunner, run_dir: pathlib.Path, terraform_dir: pathlib.Path) -> pathlib.Path:
    run_dir = run_dir.expanduser().resolve()
    terraform_dir = terraform_dir.expanduser().resolve()
    if not terraform_dir.is_dir():
        raise LifecycleError(f"Terraform directory does not exist: {terraform_dir}")
    BackendValidator(aws).validate(config, require_empty=False)
    store = ManifestStore(config, aws, run_dir)
    store.load_local()
    backend_file = run_dir / "backend.hcl"
    backend_file.write_text(backend_config_text(config))
    os.chmod(backend_file, 0o600)
    data_dir = run_dir / "terraform-data"
    data_dir.mkdir(mode=0o700, exist_ok=True)
    env = child_environment(config, TF_DATA_DIR=str(data_dir.resolve()), TF_IN_AUTOMATION="1")
    runner.run(
        ["terraform", "init", "-input=false", "-reconfigure", "-lockfile=readonly", f"-backend-config={backend_file}"],
        env=env,
        cwd=terraform_dir,
    )
    return backend_file


def protected_plan_path(run_dir: pathlib.Path, requested: pathlib.Path | None, filename: str) -> pathlib.Path:
    run_dir = run_dir.expanduser().resolve()
    path = (run_dir / filename) if requested is None else requested.expanduser().resolve()
    path = path.resolve()
    if path.parent != run_dir:
        raise LifecycleError("saved plans must remain directly inside the protected absolute run directory")
    return path


@serialized_run_operation
def terraform_plan(
    config: RunConfig,
    aws: AwsCLI,
    runner: CommandRunner,
    run_dir: pathlib.Path,
    terraform_dir: pathlib.Path,
    *,
    plan_path: pathlib.Path | None = None,
    replace_address: str | None = None,
) -> pathlib.Path:
    run_dir = run_dir.expanduser().resolve()
    terraform_dir = terraform_dir.expanduser().resolve()
    store = ManifestStore(config, aws, run_dir)
    manifest = store.recover()
    if store.remote_etag is None:
        raise LifecycleError("protected plan requires the current durable manifest ETag")
    previous_plan = manifest.get("saved_plan")
    if (
        isinstance(previous_plan, dict)
        and previous_plan.get("apply_started") is True
        and previous_plan.get("applied") is not True
    ):
        raise LifecycleError("a previous apply started without reaching readiness; only cleanup is safe")
    allowed_phases = {"key_rotated", "replacement_planned"} if replace_address else {"prepared", "planned"}
    if manifest.get("phase") not in allowed_phases:
        raise LifecycleError("protected plan is not allowed from the current durable lifecycle phase")
    artifact = artifact_for_recovery(config, manifest, aws, run_dir)
    source_dir, source_identity = materialize_reviewed_terraform_source(
        runner, terraform_dir, run_dir, str(artifact["revision"])
    )
    durable_source = manifest.get("terraform_source")
    if replace_address and (
        not isinstance(durable_source, dict) or terraform_source_identity(durable_source) != source_identity
    ):
        raise LifecycleError("replacement Terraform source differs from the initial reviewed deployment source")
    source_record = terraform_source_record(source_dir, source_identity)
    variable_file = write_runtime_variables(config, store, manifest, artifact)
    terraform_init(config, aws, runner, run_dir, source_dir)
    destination = protected_plan_path(run_dir, plan_path, "replace.tfplan" if replace_address else "apply.tfplan")
    args = [
        "terraform",
        "plan",
        "-input=false",
        f"-out={destination}",
        f"-var-file={variable_file.resolve()}",
    ]
    if replace_address:
        if replace_address not in {"aws_instance.envelope_west", "aws_instance.envelope_east"}:
            raise LifecycleError("replacement address must be one exact regional Envelope instance")
        args.append(f"-replace={replace_address}")
    env = child_environment(config, TF_DATA_DIR=str((run_dir / "terraform-data").resolve()), TF_IN_AUTOMATION="1")
    runner.run(args, env=env, cwd=source_dir)
    os.chmod(destination, 0o600)
    plan_json = pathlib.Path(str(destination) + ".json")
    rendered = runner.run(["terraform", "show", "-json", str(destination)], env=env, cwd=source_dir)
    if terraform_source_digest(source_dir) != source_identity["sha256"]:
        raise LifecycleError("reviewed Terraform source changed while the protected plan was produced")
    try:
        document = json.loads(rendered)
    except json.JSONDecodeError as error:
        raise LifecycleError("Terraform produced invalid saved-plan JSON") from error
    failures = validate_saved_plan(
        document,
        config.run_id,
        {replace_address} if replace_address else set(),
        {site: set(config.sites[site]["azs"]) for site in ("west", "east")},
    )
    if failures:
        raise LifecycleError("saved plan failed protected shape validation: " + "; ".join(failures))
    plan_json.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    os.chmod(plan_json, 0o600)
    manifest["phase"] = "replacement_planned" if replace_address else "planned"
    manifest["saved_plan"] = {
        "path": str(destination),
        "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
        "replacement": replace_address,
        "source": source_identity,
        "apply_started": False,
        "applied": False,
    }
    manifest["terraform_source"] = durable_source if replace_address else source_record
    store.write(manifest, if_match=store.remote_etag)
    return destination


@serialized_run_operation
def terraform_apply(
    config: RunConfig,
    aws: AwsCLI,
    runner: CommandRunner,
    run_dir: pathlib.Path,
    terraform_dir: pathlib.Path,
    plan_path: pathlib.Path | None = None,
    tailscale_factory: Callable[[], TailscaleAPI] | None = None,
) -> dict[str, Any]:
    run_dir = run_dir.expanduser().resolve()
    terraform_dir = terraform_dir.expanduser().resolve()
    store = ManifestStore(config, aws, run_dir)
    manifest = store.recover()
    if store.remote_etag is None:
        raise LifecycleError("protected apply requires the current durable manifest ETag")
    destination = protected_plan_path(run_dir, plan_path, "apply.tfplan")
    saved = manifest.get("saved_plan", {})
    if saved.get("path") != str(destination) or saved.get("sha256") != hashlib.sha256(destination.read_bytes()).hexdigest():
        raise LifecycleError("apply plan identity differs from the durably reviewed saved plan")
    if saved.get("apply_started") is not False or saved.get("applied") is not False:
        raise LifecycleError("a protected saved plan may be applied exactly once")
    expected_phase = "replacement_planned" if saved.get("replacement") else "planned"
    if manifest.get("phase") != expected_phase:
        raise LifecycleError("protected apply requires the exact durably planned lifecycle phase")
    durable_source = manifest.get("terraform_source")
    if not isinstance(durable_source, dict):
        raise LifecycleError("apply has no durable Terraform source bundle")
    source_identity = terraform_source_identity(durable_source)
    if saved.get("source") != source_identity:
        raise LifecycleError("apply Terraform source identity differs from the durably reviewed saved plan")
    manifest["saved_plan"]["apply_started"] = True
    manifest["phase"] = "apply_claimed"
    manifest["apply_claimed_at"] = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    store.write(manifest, if_match=store.remote_etag)
    try:
        source_dir, materialized_identity = materialize_durable_terraform_source(durable_source, run_dir)
        if materialized_identity != source_identity:
            raise LifecycleError("apply Terraform source bundle changed after its durable claim")
        terraform_init(config, aws, runner, run_dir, source_dir)
        replacement = saved.get("replacement")
        if replacement:
            if replacement not in {"aws_instance.envelope_west", "aws_instance.envelope_east"} or tailscale_factory is None:
                raise LifecycleError("replacement apply requires one exact regional Tailnet retirement authority")
            retire_replacement_devices(tailscale_factory(), store, manifest, str(replacement))
        manifest["tailnet"]["nodes_expected"] = True
        manifest["phase"] = "apply_started"
        store.write(manifest)
        env = child_environment(config, TF_DATA_DIR=str((run_dir / "terraform-data").resolve()), TF_IN_AUTOMATION="1")
        runner.run(["terraform", "apply", "-input=false", str(destination)], env=env, cwd=source_dir)
        output = runner.run(["terraform", "output", "-json"], env=env, cwd=source_dir)
        try:
            deployment = json.loads(output)
        except json.JSONDecodeError as error:
            raise LifecycleError("Terraform output after apply is not valid JSON") from error
        deployment_values(deployment)
        deployment_path = run_dir / "deployment.json"
        deployment_path.write_text(json.dumps(deployment, sort_keys=True, separators=(",", ":")) + "\n")
        os.chmod(deployment_path, 0o600)
        manifest["phase"] = "applied"
        manifest["saved_plan"]["applied"] = True
        manifest.pop("apply_claimed_at", None)
        manifest["deployment"] = deployment
        store.write(manifest)
        return deployment
    except Exception as error:
        manifest["phase"] = "apply_failed"
        manifest.pop("apply_claimed_at", None)
        try:
            store.write(manifest)
        except Exception as persistence_error:
            raise LifecycleError(f"apply failed and its durable failure boundary could not be persisted: {persistence_error}") from error
        raise


@serialized_run_operation
def terraform_verify_no_drift(
    config: RunConfig,
    aws: AwsCLI,
    runner: CommandRunner,
    run_dir: pathlib.Path,
    terraform_dir: pathlib.Path,
) -> None:
    run_dir = run_dir.expanduser().resolve()
    terraform_dir = terraform_dir.expanduser().resolve()
    store = ManifestStore(config, aws, run_dir)
    manifest = store.load_local()
    artifact = artifact_for_recovery(config, manifest, aws, run_dir)
    durable_source = manifest.get("terraform_source")
    if not isinstance(durable_source, dict):
        raise LifecycleError("no-drift verification has no durable Terraform source bundle")
    source_dir, source_identity = materialize_durable_terraform_source(durable_source, run_dir)
    if source_identity["revision"] != artifact["revision"]:
        raise LifecycleError("no-drift Terraform source differs from the initial reviewed deployment source")
    variable_file = write_runtime_variables(config, store, manifest, artifact)
    terraform_init(config, aws, runner, run_dir, source_dir)
    env = child_environment(config, TF_DATA_DIR=str((run_dir / "terraform-data").resolve()), TF_IN_AUTOMATION="1")
    args = [
        "terraform",
        "plan",
        "-input=false",
        "-detailed-exitcode",
        f"-var-file={variable_file.resolve()}",
    ]
    try:
        runner.run(args, env=env, cwd=source_dir)
    except CommandError as error:
        if error.returncode == 2:
            raise LifecycleError("protected no-drift verification detected Terraform changes") from error
        raise


READINESS_COMMANDS = [
    "set -euo pipefail",
    "/usr/bin/timeout --signal=TERM --kill-after=5s 600s cloud-init status --wait --long",
    """if /usr/bin/timeout --signal=KILL 120s /bin/bash <<'ENVELOPE_READINESS'
set -uo pipefail
while true; do
  units_ready=true
  for unit in tailscaled.service envelope-host-network.service envelope.service; do
    systemctl is-active --quiet "$unit" || units_ready=false
  done
  if [[ "$units_ready" == true ]] &&
    PREFLIGHT_MAX_ATTEMPTS=1 PREFLIGHT_RETRY_SECONDS=0 /usr/bin/timeout --signal=TERM --kill-after=2s 20s /usr/local/sbin/envelope-preflight >/dev/null 2>&1 &&
    curl --fail --silent --max-time 5 http://127.0.0.1:9090/healthz >/dev/null 2>&1; then
    exit 0
  fi
  sleep 2
ENVELOPE_READINESS
then
  exit 0
fi
failed=0
for unit in tailscaled.service envelope-host-network.service envelope.service; do
  systemctl is-active "$unit" >&2 || failed=1
done
PREFLIGHT_MAX_ATTEMPTS=1 PREFLIGHT_RETRY_SECONDS=0 /usr/bin/timeout --signal=TERM --kill-after=2s 20s /usr/local/sbin/envelope-preflight >&2 || failed=1
curl --fail --silent --show-error --max-time 5 http://127.0.0.1:9090/healthz >&2 || failed=1
exit 1""",
]


def invocation_does_not_exist(error: Exception) -> bool:
    return isinstance(error, CommandError) and "InvocationDoesNotExist" in error.raw_stderr


def cancel_ssm_command(
    aws: AwsCLI,
    *,
    region: str,
    instance_id: str,
    command_id: str,
    sleep: Any = time.sleep,
    timeout_seconds: int = 30,
) -> str:
    aws.json(["ssm", "cancel-command", "--command-id", command_id], region=region)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            invocation = aws.json(
                ["ssm", "get-command-invocation", "--command-id", command_id, "--instance-id", instance_id],
                region=region,
            )
        except CommandError as error:
            if invocation_does_not_exist(error):
                sleep(2)
                continue
            raise
        status = str(invocation.get("Status", "Unknown"))
        if status in {"Success", "Cancelled", "Failed", "TimedOut"}:
            return status
        sleep(2)
    raise LifecycleError(f"SSM command cancellation was not confirmed in {region}")


def wait_for_instance(aws: AwsCLI, *, region: str, instance_id: str, deadline: float, sleep: Any = time.sleep) -> None:
    while time.monotonic() < deadline:
        response = aws.json(
            ["ssm", "describe-instance-information", "--filters", f"Key=InstanceIds,Values={instance_id}"], region=region
        )
        entries = response.get("InstanceInformationList", [])
        if len(entries) == 1 and entries[0].get("PingStatus") == "Online":
            payload = json.dumps(
                {"commands": READINESS_COMMANDS, "executionTimeout": ["750"]}, separators=(",", ":")
            )
            sent = aws.json(
                [
                    "ssm",
                    "send-command",
                    "--instance-ids",
                    instance_id,
                    "--document-name",
                    "AWS-RunShellScript",
                    "--parameters",
                    payload,
                    "--timeout-seconds",
                    "300",
                ],
                region=region,
            )
            command_id = sent.get("Command", {}).get("CommandId")
            if not command_id:
                raise LifecycleError(f"SSM readiness command for {region} returned no command id")
            while time.monotonic() < deadline:
                try:
                    invocation = aws.json(
                        ["ssm", "get-command-invocation", "--command-id", command_id, "--instance-id", instance_id],
                        region=region,
                    )
                except Exception as error:
                    if invocation_does_not_exist(error):
                        sleep(2)
                        continue
                    try:
                        cancel_ssm_command(
                            aws,
                            region=region,
                            instance_id=instance_id,
                            command_id=str(command_id),
                            sleep=sleep,
                        )
                    except Exception as cancellation_error:
                        raise LifecycleError(
                            f"SSM readiness polling and cancellation failed in {region}: {error}; {cancellation_error}"
                        ) from error
                    raise LifecycleError(f"SSM readiness polling failed in {region} after confirmed stop: {error}") from error
                status = invocation.get("Status")
                if status == "Success":
                    return
                if status in {"Cancelled", "Failed", "TimedOut"}:
                    raise LifecycleError(redact(f"SSM readiness failed in {region}: {invocation.get('StandardErrorContent', '')}"))
                sleep(5)
            try:
                cancel_ssm_command(
                    aws,
                    region=region,
                    instance_id=instance_id,
                    command_id=str(command_id),
                    sleep=sleep,
                )
            except Exception as error:
                raise LifecycleError(f"SSM readiness timed out in {region} and command cancellation failed: {error}") from error
            raise LifecycleError(f"SSM readiness timed out for instance in {region}")
        sleep(5)
    raise LifecycleError(f"SSM readiness timed out for instance in {region}")


def wait_for_target(aws: AwsCLI, *, region: str, target_group_arn: str, deadline: float, sleep: Any = time.sleep) -> None:
    last_state = "unknown"
    while time.monotonic() < deadline:
        response = aws.json(
            ["elbv2", "describe-target-health", "--target-group-arn", target_group_arn], region=region
        )
        descriptions = response.get("TargetHealthDescriptions", [])
        if len(descriptions) != 1:
            last_state = f"target-count-{len(descriptions)}"
        else:
            health = descriptions[0].get("TargetHealth", {})
            last_state = str(health.get("State", "unknown"))
            if last_state == "healthy":
                return
        sleep(5)
    raise LifecycleError(f"GWLB target in {region} did not become healthy; last state={last_state}")


def collect_diagnostics(
    aws: AwsCLI,
    site: dict[str, str],
    instance_id: str,
    *,
    sleep: Any = time.sleep,
) -> dict[str, str]:
    payload = json.dumps(
        {"commands": ["/usr/local/sbin/envelope-diagnostics"], "executionTimeout": ["90"]},
        separators=(",", ":"),
    )
    sent = aws.json(
        [
            "ssm",
            "send-command",
            "--instance-ids",
            instance_id,
            "--document-name",
            "AWS-RunShellScript",
            "--parameters",
            payload,
            "--timeout-seconds",
            "120",
        ],
        region=site["region"],
    )
    command_id = str(sent.get("Command", {}).get("CommandId", ""))
    if not command_id:
        return {"command_id": "unavailable", "status": "send-failed", "stdout": "", "stderr": ""}
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            invocation = aws.json(
                ["ssm", "get-command-invocation", "--command-id", command_id, "--instance-id", instance_id],
                region=site["region"],
            )
        except Exception as error:
            if invocation_does_not_exist(error):
                sleep(2)
                continue
            try:
                stopped = cancel_ssm_command(
                    aws,
                    region=site["region"],
                    instance_id=instance_id,
                    command_id=command_id,
                    sleep=sleep,
                )
            except Exception as cancellation_error:
                detail = redact(f"diagnostic polling failed and cancellation was not confirmed: {error}; {cancellation_error}")
                return {"command_id": command_id, "status": "PollFailed", "stdout": "", "stderr": detail[:32768]}
            detail = redact(f"diagnostic polling failed after confirmed {stopped}: {error}")
            return {"command_id": command_id, "status": "PollFailed", "stdout": "", "stderr": detail[:32768]}
        status = str(invocation.get("Status", "Unknown"))
        if status not in {"Pending", "InProgress", "Delayed", "Cancelling"}:
            return {
                "command_id": command_id,
                "status": status,
                "stdout": redact(str(invocation.get("StandardOutputContent", ""))[:32768]),
                "stderr": redact(str(invocation.get("StandardErrorContent", ""))[:32768]),
            }
        sleep(2)
    try:
        stopped = cancel_ssm_command(
            aws,
            region=site["region"],
            instance_id=instance_id,
            command_id=command_id,
            sleep=sleep,
        )
        detail = f"diagnostic poll timed out; remote command stopped with {stopped}"
    except Exception as error:
        detail = redact(f"diagnostic poll timed out; cancellation was not confirmed: {error}")
    return {"command_id": command_id, "status": "TimedOut", "stdout": "", "stderr": detail}


def deployment_values(document: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    def output_value(name: str) -> Any:
        value = document.get(name)
        if isinstance(value, dict) and "value" in value:
            return value["value"]
        return value

    instances = output_value("instance_ids")
    target_groups = output_value("gwlb_target_group_arns")
    if not isinstance(instances, dict) or not isinstance(target_groups, dict):
        raise LifecycleError("deployment JSON must contain instance_ids and gwlb_target_group_arns outputs")
    if set(instances) != {"west", "east"} or set(target_groups) != {"west", "east"}:
        raise LifecycleError("deployment outputs must contain exactly west and east")
    return ({site: str(instances[site]) for site in instances}, {site: str(target_groups[site]) for site in target_groups})


def wait_deployment(
    config: RunConfig,
    aws: AwsCLI,
    deployment: dict[str, Any],
    *,
    timeout_seconds: int,
    evidence_path: pathlib.Path | None = None,
) -> None:
    instances, target_groups = deployment_values(deployment)
    deadline = time.monotonic() + timeout_seconds
    try:
        for site in ("west", "east"):
            wait_for_instance(
                aws,
                region=config.sites[site]["region"],
                instance_id=instances[site],
                deadline=deadline,
            )
        for site in ("west", "east"):
            wait_for_target(
                aws,
                region=config.sites[site]["region"],
                target_group_arn=target_groups[site],
                deadline=deadline,
            )
    except Exception as error:
        diagnostics: dict[str, Any] = {}
        for site in ("west", "east"):
            try:
                diagnostics[site] = collect_diagnostics(aws, config.sites[site], instances[site])
            except Exception as diagnostic_error:
                diagnostics[site] = {
                    "command_id": "unavailable",
                    "status": "collection-failed",
                    "stdout": "",
                    "stderr": redact(str(diagnostic_error))[:32768],
                }
        diagnostics["target_health"] = {}
        for site in ("west", "east"):
            try:
                target_response = aws.json(
                    ["elbv2", "describe-target-health", "--target-group-arn", target_groups[site]],
                    region=config.sites[site]["region"],
                )
                diagnostics["target_health"][site] = [
                    {
                        "target": value.get("Target", {}).get("Id"),
                        "state": value.get("TargetHealth", {}).get("State"),
                        "reason": value.get("TargetHealth", {}).get("Reason"),
                        "description": value.get("TargetHealth", {}).get("Description"),
                    }
                    for value in target_response.get("TargetHealthDescriptions", [])
                    if isinstance(value, dict)
                ]
            except Exception as target_error:
                diagnostics["target_health"][site] = {"error": redact(str(target_error))[:2048]}
        if evidence_path is not None:
            evidence_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            evidence_path.write_text(json.dumps(diagnostics, sort_keys=True, separators=(",", ":")) + "\n")
            os.chmod(evidence_path, 0o600)
        diagnostic_ids = {site: diagnostics[site]["command_id"] for site in ("west", "east")}
        raise LifecycleError(f"deployment readiness failed; redacted diagnostics={evidence_path}; command ids={json.dumps(diagnostic_ids, sort_keys=True)}: {error}") from error


def device_hostname(device: dict[str, Any]) -> str:
    return str(device.get("hostname") or device.get("name") or "").split(".")[0]


def scoped_run_devices(
    devices: list[dict[str, Any]],
    manifest: dict[str, Any],
    *,
    include_numeric_suffixes: bool = False,
) -> dict[str, list[dict[str, Any]]]:
    expected = {str(value) for value in manifest["tailnet"]["expected_hostnames"]}
    required_tag = str(manifest["tailnet"]["tag"])
    result = {hostname: [] for hostname in expected}
    for device in devices:
        hostname = device_hostname(device)
        tags = {str(value) for value in device.get("tags", [])}
        if required_tag not in tags or not device.get("id"):
            continue
        for expected_hostname in expected:
            if hostname == expected_hostname or include_numeric_suffixes and re.fullmatch(
                re.escape(expected_hostname) + r"-[1-9][0-9]*", hostname
            ):
                result[expected_hostname].append(device)
                break
    return result


def record_ready_devices(tailscale: TailscaleAPI, store: ManifestStore, manifest: dict[str, Any]) -> dict[str, str]:
    scoped = scoped_run_devices(tailscale.list_devices(), manifest)
    if any(len(values) != 1 for values in scoped.values()):
        raise LifecycleError("readiness must identify exactly one full-field Tailnet device for each run hostname")
    identifiers = {
        hostname.rsplit("-", 1)[1]: str(values[0]["id"])
        for hostname, values in scoped.items()
    }
    if set(identifiers) != {"west", "east"} or len(set(identifiers.values())) != 2:
        raise LifecycleError("Tailnet device identities are not distinct west/east run nodes")
    manifest["tailnet"]["device_ids"] = identifiers
    manifest["tailnet"].pop("replacement_retirement", None)
    manifest["tailnet"]["nodes_expected"] = True
    manifest.pop("readiness_started_at", None)
    manifest["phase"] = "ready"
    store.write(manifest)
    return identifiers


@serialized_run_operation
def wait_and_record(
    config: RunConfig,
    aws: AwsCLI,
    tailscale: TailscaleAPI,
    run_dir: pathlib.Path,
    deployment: dict[str, Any],
    *,
    timeout_seconds: int,
) -> None:
    store = ManifestStore(config, aws, run_dir)
    manifest = store.recover()
    if store.remote_etag is None:
        raise LifecycleError("protected readiness requires the current durable manifest ETag")
    if manifest.get("phase") not in {"applied", "readiness_started", "readiness_failed", "ready"}:
        raise LifecycleError("protected readiness is not allowed from the current durable lifecycle phase")
    if manifest.get("deployment") != deployment:
        raise LifecycleError("readiness deployment identity differs from the durable applied outputs")
    manifest["tailnet"]["nodes_expected"] = True
    manifest["phase"] = "readiness_started"
    manifest["readiness_started_at"] = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    store.write(manifest, if_match=store.remote_etag)
    try:
        wait_deployment(
            config,
            aws,
            deployment,
            timeout_seconds=timeout_seconds,
            evidence_path=run_dir.expanduser().resolve() / "diagnostics.json",
        )
        record_ready_devices(tailscale, store, manifest)
    except Exception:
        manifest.pop("readiness_started_at", None)
        manifest["phase"] = "readiness_failed"
        store.write(manifest)
        raise


def retire_replacement_devices(
    tailscale: TailscaleAPI,
    store: ManifestStore,
    manifest: dict[str, Any],
    replacement_address: str,
) -> list[str]:
    site = replacement_address.rsplit("_", 1)[-1]
    if site not in {"west", "east"}:
        raise LifecycleError("replacement Tailnet retirement site is invalid")
    expected = [str(value) for value in manifest["tailnet"]["expected_hostnames"] if str(value).endswith(f"-{site}")]
    if len(expected) != 1:
        raise LifecycleError("replacement Tailnet retirement has no exact site hostname")
    scoped = scoped_run_devices(tailscale.list_devices(), manifest, include_numeric_suffixes=True)
    candidates = scoped[expected[0]]
    recorded = manifest["tailnet"].get("device_ids", {})
    pending = manifest["tailnet"].get("replacement_retirement")
    if pending:
        if not isinstance(pending, dict) or pending.get("site") != site or not isinstance(pending.get("device_ids"), list):
            raise LifecycleError("durable replacement Tailnet retirement identity is invalid")
        candidate_ids = sorted({str(value) for value in pending["device_ids"] if isinstance(value, str) and value})
        if not candidate_ids or len(candidate_ids) != len(pending["device_ids"]):
            raise LifecycleError("durable replacement Tailnet retirement IDs are invalid")
    else:
        if not isinstance(recorded, dict) or set(recorded) != {"west", "east"}:
            raise LifecycleError("replacement requires exact durable west/east Tailnet device IDs")
        if any(not isinstance(value, str) or not value for value in recorded.values()):
            raise LifecycleError("replacement requires non-empty durable Tailnet device IDs")
        candidate_ids = sorted({str(recorded[site]), *(str(device["id"]) for device in candidates)})
        manifest["tailnet"]["device_ids"] = {
            recorded_site: str(device_id)
            for recorded_site, device_id in recorded.items()
            if recorded_site != site
        }
        manifest["tailnet"]["replacement_retirement"] = {"site": site, "device_ids": candidate_ids}
        manifest["phase"] = "replacement_device_retirement_started"
        store.write(manifest)
    present_ids = {str(device["id"]) for device in tailscale.list_devices() if device.get("id")}
    for device_id in candidate_ids:
        if device_id not in present_ids:
            continue
        tailscale.delete_device(device_id)
    remaining = scoped_run_devices(tailscale.list_devices(), manifest, include_numeric_suffixes=True)[expected[0]]
    if remaining:
        raise LifecycleError("replacement Tailnet device retirement left a run-scoped site node")
    retired = {str(value) for value in manifest["tailnet"].get("retired_device_ids", [])}
    manifest["tailnet"]["retired_device_ids"] = sorted(retired.union(candidate_ids))
    manifest["phase"] = "replacement_device_retired"
    store.write(manifest)
    return candidate_ids


def cleanup_tailnet_devices(tailscale: TailscaleAPI, manifest: dict[str, Any], *, dry_run: bool) -> list[str]:
    devices = tailscale.list_devices()
    expected_hostnames = {str(value) for value in manifest["tailnet"]["expected_hostnames"]}
    required_tag = str(manifest["tailnet"]["tag"])
    recorded = manifest["tailnet"].get("device_ids", {})
    pending = manifest["tailnet"].get("replacement_retirement")
    if not isinstance(recorded, dict) or not set(recorded).issubset({"west", "east"}) or any(
        not isinstance(value, str) or not value for value in recorded.values()
    ):
        raise LifecycleError("durable Tailnet node IDs have an invalid site identity")
    pending_site: str | None = None
    pending_ids: list[str] = []
    if pending is not None:
        if (
            not isinstance(pending, dict)
            or pending.get("site") not in {"west", "east"}
            or not isinstance(pending.get("device_ids"), list)
            or any(not isinstance(value, str) or not value for value in pending["device_ids"])
        ):
            raise LifecycleError("durable replacement Tailnet retirement identity is invalid")
        pending_site = str(pending["site"])
        pending_ids = list(pending["device_ids"])
        if pending_site in recorded:
            raise LifecycleError("replacement Tailnet retirement site is still present in durable node IDs")
    selected_set = {str(value) for value in recorded.values()}.union(pending_ids)
    by_id = {str(device.get("id")): device for device in devices if device.get("id")}
    site_hostnames = {hostname.rsplit("-", 1)[-1]: hostname for hostname in expected_hostnames}
    for site, device_id in recorded.items():
        device = by_id.get(str(device_id))
        if device is None:
            continue
        if device_hostname(device) != site_hostnames[site] or required_tag not in {
            str(value) for value in device.get("tags", [])
        }:
            raise LifecycleError("recorded Tailnet device ID no longer has the durable run hostname and tag")
    if pending_site is not None:
        expected = site_hostnames[pending_site]
        for device_id in pending_ids:
            device = by_id.get(device_id)
            if device is None:
                continue
            hostname = device_hostname(device)
            if (
                hostname != expected
                and re.fullmatch(re.escape(expected) + r"-[1-9][0-9]*", hostname) is None
            ) or required_tag not in {str(value) for value in device.get("tags", [])}:
                raise LifecycleError("pending replacement Tailnet device ID left its durable hostname/tag scope")
        current = [
            device
            for device in scoped_run_devices(devices, manifest, include_numeric_suffixes=True)[expected]
            if str(device["id"]) not in selected_set
        ]
        if len(current) > 1:
            raise LifecycleError("replacement recovery found ambiguous current Tailnet nodes")
        selected_set.update(str(device["id"]) for device in current)
    if not selected_set and manifest["tailnet"].get("nodes_expected"):
        scoped = scoped_run_devices(devices, manifest, include_numeric_suffixes=True)
        if any(len(values) > 1 for values in scoped.values()):
            raise LifecycleError("partial-recovery Tailnet fallback found an ambiguous duplicate hostname/tag identity")
        selected_set = {str(values[0]["id"]) for values in scoped.values() if values}
        if len(selected_set) != sum(1 for values in scoped.values() if values):
            raise LifecycleError("partial-recovery Tailnet fallback found one device ID under multiple identities")
    elif not selected_set:
        return []
    selected = sorted(selected_set)
    if dry_run:
        return selected
    for device_id in selected:
        tailscale.delete_device(device_id)
    remaining = tailscale.list_devices()
    remaining_ids = {str(device.get("id")) for device in remaining if device.get("id")}
    if remaining_ids.intersection(selected):
        raise LifecycleError("Tailnet device deletion did not remove every exact recorded node ID")
    fallback_remaining = scoped_run_devices(remaining, manifest, include_numeric_suffixes=True)
    if any(fallback_remaining.values()):
        raise LifecycleError("run-scoped Tailnet nodes remain after deletion")
    return selected


def audit_run_resources(config: RunConfig, aws: AwsCLI) -> list[dict[str, str]]:
    tagged: dict[str, dict[str, str]] = {}
    for site in ("west", "east"):
        response = aws.json(
            [
                "resourcegroupstaggingapi",
                "get-resources",
                "--tag-filters",
                f"Key=EnvelopeRun,Values={config.run_id}",
            ],
            region=config.sites[site]["region"],
        )
        mappings = response.get("ResourceTagMappingList")
        if not isinstance(mappings, list):
            raise LifecycleError("tag audit returned an invalid resource mapping schema")
        for item in mappings:
            if not isinstance(item, dict) or not isinstance(item.get("ResourceARN"), str) or not item["ResourceARN"]:
                raise LifecycleError("tag audit returned a resource without an exact ARN")
            raw_tags = item.get("Tags")
            if not isinstance(raw_tags, list) or not all(
                isinstance(tag, dict) and isinstance(tag.get("Key"), str) and isinstance(tag.get("Value"), str)
                for tag in raw_tags
            ):
                raise LifecycleError("tag audit returned an invalid tag schema")
            tags = {str(tag["Key"]): str(tag["Value"]) for tag in raw_tags}
            if tags.get("EnvelopeRun") != config.run_id or tags.get("ExpiresAt") != config.expires_at:
                raise LifecycleError("tag audit returned a resource whose run/TTL identity is not exact")
            arn = str(item["ResourceARN"])
            service = arn.split(":", 5)[2] if arn.startswith("arn:") else ""
            effective_region = config.sites["west"]["region"] if service in {"s3", "iam"} else config.sites[site]["region"]
            candidate = {"arn": arn, "region": effective_region}
            if arn in tagged and tagged[arn] != candidate:
                raise LifecycleError("tag audit returned one resource under conflicting regional identities")
            tagged[arn] = candidate
    return [tagged[arn] for arn in sorted(tagged) if owned_resource_is_live(aws, tagged[arn])]


def owned_resource_kind(arn: str) -> tuple[str, str]:
    parts = arn.split(":", 5)
    if len(parts) != 6 or not arn.startswith("arn:"):
        raise LifecycleError(f"owned residual has an invalid ARN: {arn}")
    service, resource = parts[2], parts[5]
    if service == "s3" and resource:
        return "s3-bucket", resource
    if service == "elasticloadbalancing" and resource.startswith("loadbalancer/"):
        return "load-balancer", arn
    if service == "elasticloadbalancing" and resource.startswith("listener/"):
        return "listener", arn
    if service == "elasticloadbalancing" and resource.startswith("targetgroup/"):
        return "target-group", arn
    if service == "iam" and resource.startswith("instance-profile/"):
        return "instance-profile", resource.split("/", 1)[1]
    if service == "iam" and resource.startswith("role/"):
        return "role", resource.split("/", 1)[1]
    if service == "ssm" and resource.startswith("parameter/"):
        return "ssm-parameter", "/" + resource.split("/", 1)[1]
    if service == "ec2" and "/" in resource:
        kind, identifier = resource.split("/", 1)
        allowed = {
            "instance",
            "volume",
            "vpc-endpoint",
            "vpc-endpoint-service",
            "natgateway",
            "elastic-ip",
            "internet-gateway",
            "route-table",
            "subnet",
            "security-group",
            "network-interface",
            "vpc",
        }
        if kind in allowed:
            return kind, identifier
    raise LifecycleError(f"owned residual type is not in the cleanup allowlist: {arn}")


OWNED_RESOURCE_ABSENT_MARKERS = {
    "s3-bucket": ("(404)", "Not Found", "NoSuchBucket"),
    "load-balancer": ("LoadBalancerNotFound",),
    "listener": ("ListenerNotFound",),
    "target-group": ("TargetGroupNotFound",),
    "instance-profile": ("NoSuchEntity",),
    "role": ("NoSuchEntity",),
    "ssm-parameter": ("ParameterNotFound",),
    "instance": ("InvalidInstanceID.NotFound",),
    "volume": ("InvalidVolume.NotFound",),
    "vpc-endpoint": ("InvalidVpcEndpointId.NotFound",),
    "vpc-endpoint-service": (
        "InvalidServiceId.NotFound",
        "InvalidVpcEndpointService.NotFound",
        "InvalidVpcEndpointServiceId.NotFound",
    ),
    "natgateway": ("NatGatewayNotFound",),
    "elastic-ip": ("InvalidAllocationID.NotFound",),
    "internet-gateway": ("InvalidInternetGatewayID.NotFound",),
    "route-table": ("InvalidRouteTableID.NotFound",),
    "subnet": ("InvalidSubnetID.NotFound",),
    "security-group": ("InvalidGroup.NotFound",),
    "network-interface": ("InvalidNetworkInterfaceID.NotFound",),
    "vpc": ("InvalidVpcID.NotFound",),
}


def exact_described_item(
    response: dict[str, Any], collection: str, identity_field: str, expected: str
) -> dict[str, Any] | None:
    values = response.get(collection)
    if not isinstance(values, list):
        raise LifecycleError(f"authoritative {collection} response has an invalid schema")
    if not values:
        return None
    if not all(isinstance(value, dict) for value in values):
        raise LifecycleError(f"authoritative {collection} response contains a non-object item")
    if len(values) != 1 or values[0].get(identity_field) != expected:
        raise LifecycleError(f"authoritative {collection} response differs from the exact requested identity")
    return values[0]


def owned_resource_is_live(aws: AwsCLI, resource: dict[str, str]) -> bool:
    arn, region = resource["arn"], resource["region"]
    kind, identifier = owned_resource_kind(arn)
    try:
        if kind == "s3-bucket":
            aws.json(["s3api", "head-bucket", "--bucket", identifier], region=region)
            return True
        if kind in {"load-balancer", "listener", "target-group"}:
            operation, argument, collection, identity_field = {
                "load-balancer": ("describe-load-balancers", "--load-balancer-arns", "LoadBalancers", "LoadBalancerArn"),
                "listener": ("describe-listeners", "--listener-arns", "Listeners", "ListenerArn"),
                "target-group": ("describe-target-groups", "--target-group-arns", "TargetGroups", "TargetGroupArn"),
            }[kind]
            response = aws.json(["elbv2", operation, argument, identifier], region=region)
            return exact_described_item(response, collection, identity_field, identifier) is not None
        if kind == "instance-profile":
            response = aws.json(["iam", "get-instance-profile", "--instance-profile-name", identifier])
            profile = response.get("InstanceProfile")
            if not isinstance(profile, dict) or profile.get("InstanceProfileName") != identifier:
                raise LifecycleError("authoritative instance-profile response differs from the exact requested identity")
            return True
        if kind == "role":
            response = aws.json(["iam", "get-role", "--role-name", identifier])
            role = response.get("Role")
            if not isinstance(role, dict) or role.get("RoleName") != identifier:
                raise LifecycleError("authoritative role response differs from the exact requested identity")
            return True
        if kind == "ssm-parameter":
            response = aws.json(
                ["ssm", "describe-parameters", "--parameter-filters", f"Key=Name,Values={identifier}"], region=region
            )
            return exact_described_item(response, "Parameters", "Name", identifier) is not None
        if kind == "instance":
            response = aws.json(["ec2", "describe-instances", "--instance-ids", identifier], region=region)
            reservations = response.get("Reservations")
            if not isinstance(reservations, list) or not all(isinstance(value, dict) for value in reservations):
                raise LifecycleError("authoritative instance response has an invalid reservation schema")
            instances: list[dict[str, Any]] = []
            for reservation in reservations:
                values = reservation.get("Instances")
                if not isinstance(values, list) or not all(isinstance(value, dict) for value in values):
                    raise LifecycleError("authoritative instance response has an invalid instance schema")
                instances.extend(values)
            if not instances:
                return False
            if len(instances) != 1 or instances[0].get("InstanceId") != identifier:
                raise LifecycleError("authoritative instance response differs from the exact requested identity")
            state_value = instances[0].get("State")
            if not isinstance(state_value, dict):
                raise LifecycleError("authoritative instance response omitted its state object")
            state = state_value.get("Name")
            if not isinstance(state, str):
                raise LifecycleError("authoritative instance response omitted its state")
            return state.lower() != "terminated"
        if kind == "natgateway":
            response = aws.json(["ec2", "describe-nat-gateways", "--nat-gateway-ids", identifier], region=region)
            gateway = exact_described_item(response, "NatGateways", "NatGatewayId", identifier)
            if gateway is None:
                return False
            state = gateway.get("State")
            if not isinstance(state, str):
                raise LifecycleError("authoritative NAT gateway response omitted its state")
            return state.lower() not in {"deleted", "failed"}
        ec2_specs = {
            "volume": ("describe-volumes", "--volume-ids", "Volumes", "VolumeId"),
            "vpc-endpoint": ("describe-vpc-endpoints", "--vpc-endpoint-ids", "VpcEndpoints", "VpcEndpointId"),
            "vpc-endpoint-service": (
                "describe-vpc-endpoint-service-configurations",
                "--service-ids",
                "ServiceConfigurations",
                "ServiceId",
            ),
            "elastic-ip": ("describe-addresses", "--allocation-ids", "Addresses", "AllocationId"),
            "internet-gateway": (
                "describe-internet-gateways",
                "--internet-gateway-ids",
                "InternetGateways",
                "InternetGatewayId",
            ),
            "route-table": ("describe-route-tables", "--route-table-ids", "RouteTables", "RouteTableId"),
            "subnet": ("describe-subnets", "--subnet-ids", "Subnets", "SubnetId"),
            "security-group": ("describe-security-groups", "--group-ids", "SecurityGroups", "GroupId"),
            "network-interface": (
                "describe-network-interfaces",
                "--network-interface-ids",
                "NetworkInterfaces",
                "NetworkInterfaceId",
            ),
            "vpc": ("describe-vpcs", "--vpc-ids", "Vpcs", "VpcId"),
        }
        operation, argument, collection, identity_field = ec2_specs[kind]
        response = aws.json(["ec2", operation, argument, identifier], region=region)
        item = exact_described_item(response, collection, identity_field, identifier)
        if item is None:
            return False
        if kind in {"volume", "vpc-endpoint", "vpc-endpoint-service"}:
            state_field = {"volume": "State", "vpc-endpoint": "State", "vpc-endpoint-service": "ServiceState"}[kind]
            state = item.get(state_field)
            if not isinstance(state, str):
                raise LifecycleError(f"authoritative {kind} response omitted its state")
            if state.lower() == "deleted":
                return False
        return True
    except CommandError as error:
        if any(marker in error.raw_stderr for marker in OWNED_RESOURCE_ABSENT_MARKERS[kind]):
            return False
        raise


def empty_owned_bucket(aws: AwsCLI, bucket: str, region: str) -> None:
    response = aws.json(["s3api", "list-object-versions", "--bucket", bucket], region=region)
    for collection in ("Versions", "DeleteMarkers"):
        for item in response.get(collection, []):
            if isinstance(item, dict) and item.get("Key") and item.get("VersionId"):
                aws.json(
                    [
                        "s3api",
                        "delete-object",
                        "--bucket",
                        bucket,
                        "--key",
                        str(item["Key"]),
                        "--version-id",
                        str(item["VersionId"]),
                    ],
                    region=region,
                )
    remaining = aws.json(["s3api", "list-object-versions", "--bucket", bucket], region=region)
    if remaining.get("Versions") or remaining.get("DeleteMarkers"):
        raise LifecycleError("owned artifact bucket still has object versions after exact emptying")
    aws.json(["s3api", "delete-bucket", "--bucket", bucket], region=region)


def delete_owned_resource(aws: AwsCLI, resource: dict[str, str]) -> None:
    arn, region = resource["arn"], resource["region"]
    kind, identifier = owned_resource_kind(arn)
    if kind == "s3-bucket":
        empty_owned_bucket(aws, identifier, region)
    elif kind == "load-balancer":
        aws.json(["elbv2", "delete-load-balancer", "--load-balancer-arn", identifier], region=region)
    elif kind == "listener":
        aws.json(["elbv2", "delete-listener", "--listener-arn", identifier], region=region)
    elif kind == "target-group":
        aws.json(["elbv2", "delete-target-group", "--target-group-arn", identifier], region=region)
    elif kind == "instance":
        aws.json(["ec2", "terminate-instances", "--instance-ids", identifier], region=region)
    elif kind == "volume":
        aws.json(["ec2", "delete-volume", "--volume-id", identifier], region=region)
    elif kind == "vpc-endpoint":
        aws.json(["ec2", "delete-vpc-endpoints", "--vpc-endpoint-ids", identifier], region=region)
    elif kind == "vpc-endpoint-service":
        aws.json(["ec2", "delete-vpc-endpoint-service-configurations", "--service-ids", identifier], region=region)
    elif kind == "natgateway":
        aws.json(["ec2", "delete-nat-gateway", "--nat-gateway-id", identifier], region=region)
    elif kind == "elastic-ip":
        aws.json(["ec2", "release-address", "--allocation-id", identifier], region=region)
    elif kind == "internet-gateway":
        details = aws.json(["ec2", "describe-internet-gateways", "--internet-gateway-ids", identifier], region=region)
        for gateway in details.get("InternetGateways", []):
            for attachment in gateway.get("Attachments", []):
                if attachment.get("VpcId"):
                    aws.json(
                        ["ec2", "detach-internet-gateway", "--internet-gateway-id", identifier, "--vpc-id", str(attachment["VpcId"])],
                        region=region,
                    )
        aws.json(["ec2", "delete-internet-gateway", "--internet-gateway-id", identifier], region=region)
    elif kind == "route-table":
        details = aws.json(["ec2", "describe-route-tables", "--route-table-ids", identifier], region=region)
        for table in details.get("RouteTables", []):
            for association in table.get("Associations", []):
                if association.get("RouteTableAssociationId") and not association.get("Main"):
                    aws.json(
                        ["ec2", "disassociate-route-table", "--association-id", str(association["RouteTableAssociationId"])],
                        region=region,
                    )
        aws.json(["ec2", "delete-route-table", "--route-table-id", identifier], region=region)
    elif kind == "subnet":
        aws.json(["ec2", "delete-subnet", "--subnet-id", identifier], region=region)
    elif kind == "security-group":
        aws.json(["ec2", "delete-security-group", "--group-id", identifier], region=region)
    elif kind == "network-interface":
        aws.json(["ec2", "delete-network-interface", "--network-interface-id", identifier], region=region)
    elif kind == "vpc":
        aws.json(["ec2", "delete-vpc", "--vpc-id", identifier], region=region)
    elif kind == "instance-profile":
        profile = aws.json(["iam", "get-instance-profile", "--instance-profile-name", identifier])
        for role in profile.get("InstanceProfile", {}).get("Roles", []):
            if role.get("RoleName"):
                aws.json(
                    ["iam", "remove-role-from-instance-profile", "--instance-profile-name", identifier, "--role-name", str(role["RoleName"])]
                )
        aws.json(["iam", "delete-instance-profile", "--instance-profile-name", identifier])
    elif kind == "role":
        attached = aws.json(["iam", "list-attached-role-policies", "--role-name", identifier])
        for policy in attached.get("AttachedPolicies", []):
            if policy.get("PolicyArn"):
                aws.json(["iam", "detach-role-policy", "--role-name", identifier, "--policy-arn", str(policy["PolicyArn"])])
        inline = aws.json(["iam", "list-role-policies", "--role-name", identifier])
        for name in inline.get("PolicyNames", []):
            aws.json(["iam", "delete-role-policy", "--role-name", identifier, "--policy-name", str(name)])
        aws.json(["iam", "delete-role", "--role-name", identifier])
    elif kind == "ssm-parameter":
        aws.json(["ssm", "delete-parameter", "--name", identifier], region=region)


RESIDUAL_CLEANUP_TIMEOUT_SECONDS = 15 * 60
RESIDUAL_CLEANUP_INITIAL_BACKOFF_SECONDS = 5
RESIDUAL_CLEANUP_MAX_BACKOFF_SECONDS = 30
RESIDUAL_RETRYABLE_ERROR_MARKERS = (
    "DependencyViolation",
    "ExistingVpcEndpointConnections",
    "IncorrectState",
    "InvalidGroup.InUse",
    "InvalidIPAddress.InUse",
    "OperationNotPermitted",
    "ResourceInUse",
    "currently being deleted",
)
RESIDUAL_TERMINAL_AUTH_MARKERS = (
    "AccessDenied",
    "AuthFailure",
    "ExpiredToken",
    "InvalidClientTokenId",
    "SignatureDoesNotMatch",
    "UnauthorizedOperation",
    "UnrecognizedClientException",
)
RESIDUAL_DELETE_PRIORITY = {
    "instance": 0,
    "vpc-endpoint": 10,
    "listener": 20,
    "vpc-endpoint-service": 30,
    "load-balancer": 40,
    "target-group": 50,
    "natgateway": 60,
    "network-interface": 70,
    "volume": 80,
    "elastic-ip": 90,
    "route-table": 100,
    "security-group": 110,
    "subnet": 120,
    "internet-gateway": 130,
    "instance-profile": 140,
    "role": 150,
    "ssm-parameter": 160,
    "s3-bucket": 170,
    "vpc": 180,
}


def owned_resource_delete_priority(resource: dict[str, str]) -> tuple[int, str]:
    kind, _ = owned_resource_kind(resource["arn"])
    return RESIDUAL_DELETE_PRIORITY[kind], resource["arn"]


def remove_owned_residuals(
    config: RunConfig,
    aws: AwsCLI,
    resources: list[dict[str, str]],
    *,
    dry_run: bool,
    allow_unexpired: bool,
    sleep: Any = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> list[str]:
    expiry = dt.datetime.fromisoformat(config.expires_at.replace("Z", "+00:00"))
    if not dry_run and not allow_unexpired and expiry > dt.datetime.now(dt.timezone.utc):
        raise LifecycleError("janitor refuses to remove resources before their exact TTL expires")
    backend_arn = f"arn:aws:s3:::{config.backend['bucket']}"
    terminal_errors: dict[str, str] = {}
    terminal_arns: set[str] = set()

    def validated(candidates: list[dict[str, str]]) -> list[dict[str, str]]:
        result: list[dict[str, str]] = []
        for resource in candidates:
            if not isinstance(resource, dict):
                terminal_errors["<non-object-resource>"] = "owned cleanup residual must be an object"
                continue
            arn = resource.get("arn")
            region = resource.get("region")
            identity = str(arn or "<missing-arn>")
            try:
                if not isinstance(arn, str) or not arn or not isinstance(region, str) or not region:
                    raise LifecycleError("owned cleanup residual has an invalid ARN/region schema")
                if arn == backend_arn:
                    raise LifecycleError("shared backend infrastructure cannot be an owned cleanup residual")
                owned_resource_kind(arn)
            except LifecycleError as error:
                terminal_errors[identity] = redact(str(error))
                if isinstance(arn, str):
                    terminal_arns.add(arn)
                continue
            if arn not in terminal_arns:
                result.append(resource)
        return result

    pending = validated(resources)
    if dry_run:
        if terminal_errors:
            details = "; ".join(f"{arn}: {message}" for arn, message in sorted(terminal_errors.items()))
            raise LifecycleError(f"residual cleanup validation failed: {details}")
        return [resource["arn"] for resource in resources]
    if not resources:
        return []
    absent_markers = (
        "NotFound",
        "Not Found",
        "NoSuchEntity",
        "NoSuchBucket",
        "ParameterNotFound",
        "InvalidAllocationID.NotFound",
        "InvalidGroup.NotFound",
        "InvalidInstanceID.NotFound",
        "InvalidInternetGatewayID.NotFound",
        "InvalidRouteTableID.NotFound",
        "InvalidSubnetID.NotFound",
        "InvalidVolume.NotFound",
        "InvalidVpcID.NotFound",
    )
    retry_errors: dict[str, str] = {}
    observed = list(resources)
    deadline = monotonic() + RESIDUAL_CLEANUP_TIMEOUT_SECONDS
    backoff = RESIDUAL_CLEANUP_INITIAL_BACKOFF_SECONDS
    while pending:
        for resource in sorted(pending, key=owned_resource_delete_priority):
            arn = resource["arn"]
            try:
                delete_owned_resource(aws, resource)
            except CommandError as error:
                if any(marker in error.raw_stderr for marker in absent_markers):
                    retry_errors.pop(arn, None)
                    continue
                if any(marker in error.raw_stderr for marker in RESIDUAL_TERMINAL_AUTH_MARKERS):
                    terminal_errors[arn] = redact(str(error))
                    terminal_arns.add(arn)
                    retry_errors.pop(arn, None)
                    continue
                # Known dependencies and unclassified service errors are retried while the exact owned ARN remains.
                classification = (
                    "dependency/transient"
                    if any(marker in error.raw_stderr for marker in RESIDUAL_RETRYABLE_ERROR_MARKERS)
                    else "unclassified retryable"
                )
                retry_errors[arn] = f"{classification}: {redact(str(error))}"
            except LifecycleError as error:
                retry_errors[arn] = redact(str(error))
            else:
                retry_errors.pop(arn, None)
        try:
            observed = audit_run_resources(config, aws)
        except CommandError as error:
            if any(marker in error.raw_stderr for marker in RESIDUAL_TERMINAL_AUTH_MARKERS):
                terminal_errors["residual-audit"] = redact(str(error))
                break
            retry_errors["residual-audit"] = redact(str(error))
        except LifecycleError as error:
            terminal_errors["residual-audit"] = redact(str(error))
            break
        else:
            retry_errors.pop("residual-audit", None)
            observed_arns = {resource.get("arn") for resource in observed}
            for arn in set(retry_errors) - observed_arns:
                retry_errors.pop(arn, None)
            for arn in terminal_arns - observed_arns:
                terminal_errors.pop(arn, None)
            terminal_arns.intersection_update(observed_arns)
            pending = validated(observed)
        if not observed and not terminal_errors:
            return [resource["arn"] for resource in resources]
        if not pending:
            break
        remaining = deadline - monotonic()
        if remaining <= 0:
            break
        sleep(min(backoff, remaining))
        backoff = min(backoff * 2, RESIDUAL_CLEANUP_MAX_BACKOFF_SECONDS)
    errors = {**retry_errors, **terminal_errors}
    details = "; ".join(f"{arn}: {message}" for arn, message in sorted(errors.items()))
    suffix = f"; deletion failures: {details}" if details else ""
    raise LifecycleError(
        f"cleanup could not remove {len(observed)} allowlisted run-owned residual resource(s) "
        f"within {RESIDUAL_CLEANUP_TIMEOUT_SECONDS} seconds{suffix}"
    )


def delete_exact_object_versions(aws: AwsCLI, *, bucket: str, key: str, region: str, dry_run: bool) -> list[str]:
    versions = exact_object_versions(aws, bucket=bucket, key=key, region=region)
    if not dry_run:
        for version in versions:
            aws.json(
                [
                    "s3api",
                    "delete-object",
                    "--bucket",
                    bucket,
                    "--key",
                    key,
                    "--version-id",
                    version["version_id"],
                ],
                region=region,
            )
        if exact_object_versions(aws, bucket=bucket, key=key, region=region):
            raise LifecycleError(f"run-owned backend key still has versions after cleanup: {key}")
    return [version["version_id"] for version in versions]


def artifact_for_recovery(
    config: RunConfig,
    manifest: dict[str, Any],
    aws: AwsCLI,
    run_dir: pathlib.Path,
) -> dict[str, Any]:
    durable = manifest["artifact"]
    try:
        artifact = validate_artifact(config)
        if any(artifact.get(key) != durable.get(key) for key in ("sha256", "revision", "version", "architecture", "go_version")):
            raise LifecycleError("current artifact manifest identity differs from the durable run")
        return artifact
    except LifecycleError:
        run_dir = run_dir.expanduser().resolve()
        run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = run_dir / f"recovered-envelope-linux-{config.architecture}"
        locator = durable["object"]
        aws.json(
            [
                "s3api",
                "get-object",
                "--bucket",
                str(locator["bucket"]),
                "--key",
                str(locator["key"]),
                str(path),
            ],
            region=str(locator["region"]),
        )
        os.chmod(path, 0o700)
        try:
            inspected = inspect_artifact(
                path,
                expected_architecture=config.architecture,
                expected_sha256=str(durable["sha256"]),
                expected_revision=str(durable["revision"]),
                expected_modified=False,
                expected_go_version=str(durable["go_version"]),
                expected_version=str(durable["version"]),
                excluded_environment=config.oauth_environment_names,
            )
        except (OSError, ValueError) as error:
            raise LifecycleError(f"recovered artifact failed durable provenance verification: {error}") from error
        return {**durable, "path": str(path), "inspected": inspected}


def terraform_destroy(
    config: RunConfig,
    aws: AwsCLI,
    runner: CommandRunner,
    run_dir: pathlib.Path,
    terraform_dir: pathlib.Path,
    manifest: dict[str, Any],
) -> None:
    run_dir = run_dir.expanduser().resolve()
    terraform_dir = terraform_dir.expanduser().resolve()
    artifact = artifact_for_recovery(config, manifest, aws, run_dir)
    durable_source = manifest.get("terraform_source")
    if isinstance(durable_source, dict) and durable_source.get("files"):
        source_dir, source_identity = materialize_durable_terraform_source(durable_source, run_dir)
        if source_identity["revision"] != artifact["revision"]:
            raise LifecycleError("destroy Terraform source differs from the durable artifact revision")
    else:
        # Existing active runs created before source bundling still need a cleanup path.
        source_dir, _ = materialize_reviewed_terraform_source(
            runner, terraform_dir, run_dir, str(artifact["revision"])
        )
    store = ManifestStore(config, aws, run_dir)
    runtime_file = write_runtime_variables(config, store, manifest, artifact)
    terraform_init(config, aws, runner, run_dir, source_dir)
    env = child_environment(config, TF_DATA_DIR=str((run_dir / "terraform-data").resolve()), TF_IN_AUTOMATION="1")
    args = ["terraform", "destroy", "-auto-approve", "-input=false", f"-var-file={runtime_file.resolve()}"]
    runner.run(args, env=env, cwd=source_dir)
    remaining = runner.run(["terraform", "state", "list"], env=env, cwd=source_dir)
    if remaining.strip():
        raise LifecycleError("Terraform destroy completed with resources still in run state")


def clear_recovered_terraform_lock(config: RunConfig, aws: AwsCLI) -> None:
    aws.json(
        [
            "s3api",
            "delete-object",
            "--bucket",
            config.backend["bucket"],
            "--key",
            config.lock_key,
        ],
        region=config.backend["region"],
    )
    if aws.object_exists(config.backend["bucket"], config.lock_key, config.backend["region"]):
        raise LifecycleError("recovered Terraform lock remains after exact deletion")


@serialized_run_operation
def cleanup(
    config: RunConfig,
    aws: AwsCLI,
    tailscale: TailscaleAPI,
    runner: CommandRunner,
    run_dir: pathlib.Path,
    terraform_dir: pathlib.Path,
    *,
    recover: bool,
    dry_run: bool,
    skip_destroy: bool,
    janitor: bool = False,
) -> dict[str, Any]:
    run_dir = run_dir.expanduser().resolve()
    terraform_dir = terraform_dir.expanduser().resolve()
    store = ManifestStore(config, aws, run_dir)
    manifest = store.recover() if recover or not dry_run else store.load_local()
    if janitor and not dry_run:
        expiry = dt.datetime.fromisoformat(config.expires_at.replace("Z", "+00:00"))
        if expiry > dt.datetime.now(dt.timezone.utc):
            raise LifecycleError("janitor refuses cleanup before the durable run TTL expires")
    if not dry_run:
        if store.remote_etag is None:
            raise LifecycleError("cleanup requires the current durable manifest ETag")
        active_apply_phases = {
            "apply_claimed",
            "replacement_device_retirement_started",
            "replacement_device_retired",
            "apply_started",
        }
        if manifest.get("phase") in active_apply_phases and manifest.get("apply_claimed_at"):
            claimed = dt.datetime.fromisoformat(str(manifest["apply_claimed_at"]).replace("Z", "+00:00"))
            if dt.datetime.now(dt.timezone.utc) - claimed < dt.timedelta(minutes=30):
                raise LifecycleError("cleanup refuses a recently claimed apply that may still be running")
            if aws.object_exists(config.backend["bucket"], config.lock_key, config.backend["region"]):
                if not recover:
                    raise LifecycleError("cleanup requires explicit runner-loss recovery for a stale Terraform lock")
                clear_recovered_terraform_lock(config, aws)
        if manifest.get("phase") == "readiness_started" and manifest.get("readiness_started_at"):
            started = dt.datetime.fromisoformat(str(manifest["readiness_started_at"]).replace("Z", "+00:00"))
            if dt.datetime.now(dt.timezone.utc) - started < dt.timedelta(minutes=30):
                raise LifecycleError("cleanup refuses a recently started readiness operation")
        if str(manifest.get("phase", "")).startswith("key_rotation_") and not recover:
            raise LifecycleError("cleanup of an interrupted key rotation requires explicit recovery")
        if str(manifest.get("phase", "")).startswith("key_rotation_") and manifest.get("key_rotation_started_at"):
            started = dt.datetime.fromisoformat(str(manifest["key_rotation_started_at"]).replace("Z", "+00:00"))
            if dt.datetime.now(dt.timezone.utc) - started < dt.timedelta(minutes=30):
                raise LifecycleError("cleanup refuses a recently started key rotation")
        if manifest.get("prepare_started_at"):
            started = dt.datetime.fromisoformat(str(manifest["prepare_started_at"]).replace("Z", "+00:00"))
            if dt.datetime.now(dt.timezone.utc) - started < dt.timedelta(minutes=30):
                raise LifecycleError("cleanup refuses a recently started preparation")
        manifest["phase"] = "cleanup_started"
        store.write(manifest, if_match=store.remote_etag)
    failures: list[str] = []

    def record_failure(operation: str, error: Exception) -> None:
        failures.append(redact(f"{operation}: {error}"))

    results: dict[str, Any] = {"dry_run": dry_run, "devices": [], "parameters": [], "backend_versions": {}}
    state_exists: bool | None = None
    try:
        state_exists = aws.object_exists(config.backend["bucket"], config.backend["state_key"], config.backend["region"])
    except Exception as error:
        record_failure("inspect Terraform state object", error)
    results["state_exists"] = state_exists
    if state_exists and not skip_destroy and not dry_run:
        manifest["phase"] = "destroy_started"
        try:
            store.write(manifest)
            terraform_destroy(config, aws, runner, run_dir, terraform_dir, manifest)
        except Exception as error:
            record_failure("Terraform destroy", error)
    try:
        results["devices"] = cleanup_tailnet_devices(tailscale, manifest, dry_run=dry_run)
    except Exception as error:
        record_failure("Tailnet device cleanup", error)
    if not dry_run:
        for parameter in manifest["ssm_parameters"]:
            try:
                delete_ssm_parameter(aws, parameter)
                results["parameters"].append(f"{parameter['site']}:{parameter['name']}")
                remaining = aws.json(
                    ["ssm", "describe-parameters", "--parameter-filters", f"Key=Name,Values={parameter['name']}"],
                    region=str(parameter["region"]),
                ).get("Parameters", [])
                if remaining:
                    raise LifecycleError(f"{parameter['site']} SSM parameter remains after deletion")
            except Exception as error:
                record_failure(f"{parameter['site']} SSM parameter cleanup", error)
        try:
            key_ids = recover_auth_key_ids(tailscale, manifest)
        except Exception as error:
            key_ids = []
            record_failure("discover run auth keys", error)
        for key_id in key_ids:
            try:
                tailscale.revoke_auth_key(key_id)
            except Exception as error:
                record_failure(f"revoke run auth key {key_id}", error)
        if key_ids:
            try:
                remaining_key_ids = {str(key.get("id")) for key in tailscale.list_auth_keys() if key.get("id")}
                if remaining_key_ids.intersection(key_ids):
                    raise LifecycleError("one or more exact run auth-key IDs remain after revocation")
            except Exception as error:
                record_failure("verify run auth-key revocation", error)
    residuals: list[dict[str, str]] = []
    residual_clean = False
    try:
        residuals = audit_run_resources(config, aws)
        results["residual_count"] = len(residuals)
        if skip_destroy:
            results["residuals"] = [resource["arn"] for resource in residuals]
        else:
            results["removed_residuals"] = remove_owned_residuals(
                config,
                aws,
                residuals,
                dry_run=dry_run,
                allow_unexpired=not janitor,
            )
            residual_clean = not dry_run or not residuals
    except Exception as error:
        record_failure("allowlisted AWS residual cleanup", error)
    backend_cleanup_allowed = not skip_destroy and (dry_run or (residual_clean and not failures))
    if backend_cleanup_allowed:
        for key in (config.backend["state_key"], config.lock_key):
            try:
                results["backend_versions"][key] = delete_exact_object_versions(
                    aws,
                    bucket=config.backend["bucket"],
                    key=key,
                    region=config.backend["region"],
                    dry_run=dry_run,
                )
            except Exception as error:
                record_failure(f"delete backend versions for {key}", error)
        if dry_run or not failures:
            try:
                results["backend_versions"][config.manifest_key] = delete_exact_object_versions(
                    aws,
                    bucket=config.backend["bucket"],
                    key=config.manifest_key,
                    region=config.backend["region"],
                    dry_run=dry_run,
                )
            except Exception as error:
                record_failure(f"delete backend versions for {config.manifest_key}", error)
    if not dry_run and skip_destroy and not failures:
        manifest["phase"] = "secrets_only_cleanup_complete"
        try:
            store.write(manifest)
        except Exception as error:
            record_failure("persist secrets-only cleanup", error)
    if not dry_run and not skip_destroy and not failures:
        for path in (store.path, run_dir / "backend.hcl", run_dir / "runtime.tfvars.json"):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
    if failures:
        if not dry_run:
            manifest["phase"] = "cleanup_incomplete"
            try:
                store.write(manifest)
            except Exception as error:
                record_failure("persist incomplete cleanup", error)
        raise LifecycleError("cleanup completed independent recovery attempts; " + "; ".join(failures))
    return results


def run_directory(root: pathlib.Path, run_id: str) -> pathlib.Path:
    return root.expanduser().resolve() / run_id


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=pathlib.Path)
    parser.add_argument("--run-root", type=pathlib.Path, default=pathlib.Path(".run"))
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("preflight")
    subparsers.add_parser("prepare")
    init = subparsers.add_parser("init")
    init.add_argument("--terraform-dir", type=pathlib.Path, default=pathlib.Path("example/terraform"))
    plan = subparsers.add_parser("plan")
    plan.add_argument("--terraform-dir", type=pathlib.Path, default=pathlib.Path("example/terraform"))
    plan.add_argument("--plan-file", type=pathlib.Path)
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--terraform-dir", type=pathlib.Path, default=pathlib.Path("example/terraform"))
    apply_parser.add_argument("--plan-file", type=pathlib.Path)
    no_drift = subparsers.add_parser("verify-no-drift")
    no_drift.add_argument("--terraform-dir", type=pathlib.Path, default=pathlib.Path("example/terraform"))
    subparsers.add_parser("rotate-key")
    replacement = subparsers.add_parser("plan-replacement")
    replacement.add_argument("--terraform-dir", type=pathlib.Path, default=pathlib.Path("example/terraform"))
    replacement.add_argument("--plan-file", type=pathlib.Path)
    replacement.add_argument(
        "--replace",
        required=True,
        choices=("aws_instance.envelope_west", "aws_instance.envelope_east"),
    )
    metadata = subparsers.add_parser("metadata-preflight")
    metadata.add_argument("--artifact-only", action="store_true")
    wait = subparsers.add_parser("wait")
    wait.add_argument("--deployment-file", type=pathlib.Path, required=True)
    wait.add_argument("--timeout-seconds", type=int, default=900)
    cleanup_parser = subparsers.add_parser("cleanup")
    cleanup_parser.add_argument("--terraform-dir", type=pathlib.Path, default=pathlib.Path("example/terraform"))
    cleanup_parser.add_argument("--recover", action="store_true")
    cleanup_parser.add_argument("--dry-run", action="store_true")
    cleanup_parser.add_argument("--skip-destroy", action="store_true")
    janitor = subparsers.add_parser("janitor")
    janitor.add_argument("--terraform-dir", type=pathlib.Path, default=pathlib.Path("example/terraform"))
    janitor.add_argument("--dry-run", action="store_true")
    subparsers.add_parser("redact")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "redact":
        sys.stdout.write(redact(sys.stdin.read()))
        return 0
    if args.config is None:
        raise LifecycleError("--config is required")
    new_run_commands = {
        "metadata-preflight",
        "preflight",
        "prepare",
        "init",
        "plan",
        "apply",
        "verify-no-drift",
        "rotate-key",
        "plan-replacement",
    }
    config = RunConfig.load(args.config, enforce_future_expiry=args.command in new_run_commands)
    runner = SubprocessRunner(config.oauth_environment_names)
    aws = AwsCLI(runner, config.oauth_environment_names)
    run_dir = run_directory(args.run_root, config.run_id)
    if args.command == "metadata-preflight":
        validate_artifact(config)
        if not args.artifact_only:
            validate_aws_metadata(config, aws)
        print("metadata preflight passed")
        return 0
    tailscale = (
        build_tailscale(config)
        if args.command in {"preflight", "prepare", "wait", "rotate-key", "plan-replacement", "cleanup", "janitor"}
        else None
    )
    if args.command == "preflight":
        assert tailscale is not None
        run_preflight(config, aws, tailscale)
        print("protected preflight passed")
    elif args.command == "prepare":
        assert tailscale is not None
        prepare(config, aws, tailscale, run_dir)
        print(f"prepared run references and durable manifest for {config.run_id}")
    elif args.command == "init":
        terraform_init(config, aws, runner, run_dir, args.terraform_dir)
        print(f"initialized durable state key {config.backend['state_key']}")
    elif args.command == "plan":
        path = terraform_plan(
            config,
            aws,
            runner,
            run_dir,
            args.terraform_dir,
            plan_path=args.plan_file,
        )
        print(f"protected saved plan ready at {path}")
    elif args.command == "apply":
        terraform_apply(
            config,
            aws,
            runner,
            run_dir,
            args.terraform_dir,
            args.plan_file,
            tailscale_factory=lambda: build_tailscale(config),
        )
        print("protected saved plan applied and deployment identity persisted")
    elif args.command == "verify-no-drift":
        terraform_verify_no_drift(config, aws, runner, run_dir, args.terraform_dir)
        print("protected Terraform no-drift verification passed")
    elif args.command == "rotate-key":
        assert tailscale is not None
        rotate_auth_key(config, aws, tailscale, run_dir)
        print("rotated regional bootstrap secrets and revoked the previous auth key")
    elif args.command == "plan-replacement":
        assert tailscale is not None
        with lifecycle_lock(run_dir):
            phase = ManifestStore(config, aws, run_dir).recover().get("phase")
            if phase == "ready":
                rotate_auth_key(config, aws, tailscale, run_dir)
            elif phase not in {"key_rotated", "replacement_planned"}:
                raise LifecycleError("replacement planning cannot resume from the durable lifecycle phase")
            path = terraform_plan(
                config,
                aws,
                runner,
                run_dir,
                args.terraform_dir,
                plan_path=args.plan_file,
                replace_address=args.replace,
            )
        print(f"replacement key rotated and protected plan ready at {path}")
    elif args.command == "wait":
        assert tailscale is not None
        try:
            deployment = json.loads(args.deployment_file.expanduser().resolve().read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise LifecycleError(f"cannot read deployment output JSON: {error}") from error
        wait_and_record(
            config,
            aws,
            tailscale,
            run_dir,
            deployment,
            timeout_seconds=args.timeout_seconds,
        )
        print("both regional SSM checks and GWLB targets are ready")
    elif args.command in {"cleanup", "janitor"}:
        assert tailscale is not None
        recover = args.command == "janitor" or args.recover
        result = cleanup(
            config,
            aws,
            tailscale,
            runner,
            run_dir,
            args.terraform_dir,
            recover=recover,
            dry_run=args.dry_run,
            skip_destroy=getattr(args, "skip_destroy", False),
            janitor=args.command == "janitor",
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LifecycleError as error:
        print(redact(f"error: {error}"), file=sys.stderr)
        raise SystemExit(1)
