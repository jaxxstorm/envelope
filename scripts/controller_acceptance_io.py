"""Bounded isolated AWS sessions and immutable cross-process ownership reads."""
from __future__ import annotations

import base64
import contextlib
import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from typing import Any

import aws_production_controller_e2e as legacy
import controller_acceptance_contract as contract

OBSERVATION_APIS = {
    ("sts", "get-caller-identity"), ("iam", "get-role"), ("iam", "get-role-policy"),
    ("ec2", "describe-instances"), ("ec2", "describe-instance-status"),
    ("ec2", "describe-route-tables"), ("ec2", "describe-subnets"),
    ("ec2", "stop-instances"), ("ec2", "start-instances"),
    ("dynamodb", "get-item"), ("s3api", "get-object"), ("s3api", "list-object-versions"),
    ("s3api", "put-object"), ("ssm", "send-command"),
    ("ssm", "get-command-invocation"), ("ssm", "cancel-command"),
}
QUIESCENCE_APIS = OBSERVATION_APIS - {("ssm", "send-command"), ("ssm", "cancel-command"), ("ssm", "get-command-invocation")}


class APIError(contract.Error):
    def __init__(self, code: str):
        self.code = code
        super().__init__(f"bounded AWS request failed: {code}")


@dataclasses.dataclass
class Session:
    role_arn: str
    principal_arn: str
    access_key: str
    secret_key: str
    token: str
    expires_at: dt.datetime
    subject: str
    phase: str

    def require_lifetime(self, seconds: float = 30) -> None:
        contract.require(self.expires_at > dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds), "phase credentials are expired or inside their safety margin")
        contract.require(self.access_key.startswith("ASIA") and bool(self.secret_key) and bool(self.token), "phase requires temporary role credentials")

    def receipt(self) -> dict[str, str]:
        return {"role_arn": self.role_arn, "principal_arn_sha256": legacy.hash_identity(self.principal_arn), "expires_at": self.expires_at.isoformat().replace("+00:00", "Z"), "subject_sha256": legacy.hash_identity(self.subject)}

    def secrets(self) -> tuple[str, ...]:
        return self.access_key, self.secret_key, self.token

    def close(self) -> None:
        self.access_key = self.secret_key = self.token = ""


def _run(args: Sequence[str], environment: Mapping[str, str], *, cwd: pathlib.Path | None = None, timeout: float = 60, input_text: str | None = None) -> str:
    process = subprocess.Popen(list(args), cwd=cwd, env=dict(environment), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(input_text, timeout=timeout)
    except BaseException:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)
        raise contract.Error("bounded subprocess interrupted; forensic state retained") from None
    finally:
        # Do not leave descendants holding phase credentials after their parent exits.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    if process.returncode:
        import re
        match = re.search(r"An error occurred \(([A-Za-z0-9_.-]{1,80})\)", stderr)
        raise APIError(match.group(1) if match else "command-failed")
    contract.require(len(stdout.encode()) <= 16 * 1024 * 1024, "subprocess output exceeded its bound")
    return stdout


def clean_environment(home: pathlib.Path, region: str = "") -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME": str(home), "AWS_CONFIG_FILE": "/dev/null", "AWS_SHARED_CREDENTIALS_FILE": "/dev/null", "AWS_EC2_METADATA_DISABLED": "true", "AWS_PAGER": "", "AWS_REGION": region, "AWS_DEFAULT_REGION": region, "TF_IN_AUTOMATION": "1", "AWS_MAX_ATTEMPTS": "1"}


def assume_oidc(role_arn: str, phase: str, context: Mapping[str, str], home: pathlib.Path, duration: int) -> Session:
    contract.require(bool(contract.ROLE.fullmatch(role_arn)) and 900 <= duration <= 21600, "invalid phase role or duration")
    expected_subject = contract.subject(context, phase)
    url = urllib.parse.urlparse(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", ""))
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    contract.require(url.scheme == "https" and bool(url.hostname) and url.hostname.endswith(".actions.githubusercontent.com") and not url.username and bool(bearer), "protected GitHub OIDC endpoint is unavailable")
    query = urllib.parse.parse_qs(url.query)
    query["audience"] = ["sts.amazonaws.com"]
    request = urllib.request.Request(urllib.parse.urlunparse(url._replace(query=urllib.parse.urlencode(query, doseq=True))), headers={"Authorization": f"Bearer {bearer}"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            result = legacy.strict_json_loads(response.read(32769))
        jwt = result["value"]
        payload = jwt.split(".")[1]
        claims = legacy.strict_json_loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        contract.require(claims.get("sub") == expected_subject and claims.get("aud") == "sts.amazonaws.com" and claims.get("exp", 0) > time.time() + 30 and claims.get("exp", 0) - claims.get("iat", 0) <= 3600, "OIDC subject customization or invocation does not match the protected contract")
    except contract.Error:
        raise
    except BaseException:
        raise contract.Error("OIDC acquisition failed without retaining token material") from None
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".oidc-", dir=home)
    token_path = pathlib.Path(name)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(jwt)
        session_name = f"envelope-{phase}-{context['workflow_run_id']}-{context['attempt']}"
        result = legacy.strict_json_loads(_run(["aws", "sts", "assume-role-with-web-identity", "--role-arn", role_arn, "--role-session-name", session_name, "--web-identity-token", f"file://{token_path}", "--duration-seconds", str(duration), "--no-sign-request", "--output", "json"], clean_environment(home), timeout=30))
    finally:
        token_path.unlink(missing_ok=True)
        jwt = bearer = ""
    account, role = contract.ROLE.fullmatch(role_arn).groups()  # type: ignore[union-attr]
    expected_arn = f"arn:aws:sts::{account}:assumed-role/{role.rsplit('/', 1)[-1]}/{session_name}"
    contract.require(result.get("AssumedRoleUser", {}).get("Arn") == expected_arn, "STS returned a different phase identity")
    credentials = result.get("Credentials", {})
    session = Session(role_arn, expected_arn, credentials.get("AccessKeyId", ""), credentials.get("SecretAccessKey", ""), credentials.get("SessionToken", ""), contract.timestamp(credentials.get("Expiration")), expected_subject, phase)
    session.require_lifetime(min(duration - 60, 600))
    return session


class Commands:
    def __init__(self, session: Session, home: pathlib.Path, checkpoint: Any = None):
        self.session, self.home, self.checkpoint = session, home, checkpoint

    def run(self, args: list[str], *, env: dict[str, str] | None = None, cwd: pathlib.Path | None = None, input_text: str | None = None, timeout_seconds: float | None = None, timeout: float | None = None) -> str:
        bound = timeout_seconds or timeout or 60
        self.session.require_lifetime(bound + 5)
        name = pathlib.Path(args[0]).name
        if self.session.phase in {"observe", "quiesce"}:
            contract.require(name == "aws" and len(args) > 2 and tuple(args[1:3]) in (OBSERVATION_APIS if self.session.phase == "observe" else QUIESCENCE_APIS), "phase cannot execute deployment tools or unsupported AWS operations")
            contract.require(not any(x.split("=", 1)[0] in {"--endpoint-url", "--profile", "--cli-input-json", "--cli-input-yaml", "--no-sign-request"} for x in args), "phase cannot override AWS authority")
        environment = clean_environment(self.home)
        environment.update({"AWS_ACCESS_KEY_ID": self.session.access_key, "AWS_SECRET_ACCESS_KEY": self.session.secret_key, "AWS_SESSION_TOKEN": self.session.token})
        if env:
            for key in ("TF_DATA_DIR", "TF_PLUGIN_CACHE_DIR", "GOCACHE", "GOMODCACHE"):
                if key in env:
                    environment[key] = env[key]
        if self.checkpoint:
            self.checkpoint(args)
        return _run(args, environment, cwd=cwd, timeout=bound, input_text=input_text)


class AWS:
    def __init__(self, commands: Commands):
        self.commands = commands

    def call(self, args: list[str], *, region: str | None = None, timeout_seconds: float | None = None, timeout: float | None = None) -> str:
        suffix = ["--output", "json", "--no-cli-pager", "--cli-connect-timeout", "2", "--cli-read-timeout", "30"]
        if region:
            suffix.extend(["--region", region])
        return self.commands.run(["aws", *args, *suffix], timeout_seconds=timeout_seconds or timeout or 60)

    def json(self, args: list[str], *, region: str | None = None, timeout_seconds: float | None = None, timeout: float | None = None) -> dict[str, Any]:
        raw = self.call(args, region=region, timeout_seconds=timeout_seconds, timeout=timeout)
        return legacy._mapping(legacy.strict_json_loads(raw or "{}"), "bounded AWS response")


def read_object(aws: AWS, reference: Mapping[str, Any], directory: pathlib.Path) -> dict[str, Any]:
    ref = contract.validate_reference(reference, "immutable object")
    descriptor, name = tempfile.mkstemp(prefix=".object-", dir=directory)
    os.close(descriptor)
    path = pathlib.Path(name)
    try:
        response = aws.json(["s3api", "get-object", "--bucket", ref["bucket"], "--key", ref["key"], "--version-id", ref["version_id"], str(path)], region=ref["region"])
        contract.require(response.get("VersionId") == ref["version_id"] and path.is_file() and not path.is_symlink(), "object version was not exact")
        payload = path.read_bytes()
        contract.require(len(payload) <= 16 * 1024 * 1024 and hashlib.sha256(payload).hexdigest() == ref["sha256"], "immutable object hash differs")
        return legacy._mapping(legacy.strict_json_loads(payload), "immutable object")
    finally:
        path.unlink(missing_ok=True)


def publish_object(aws: AWS, value: Mapping[str, Any], *, bucket: str, key: str, region: str, directory: pathlib.Path, kms: str | None = None) -> dict[str, str]:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    descriptor, name = tempfile.mkstemp(prefix=".publish-", dir=directory)
    path = pathlib.Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
        args = ["s3api", "put-object", "--bucket", bucket, "--key", key, "--body", str(path), "--if-none-match", "*", "--content-type", "application/json", "--server-side-encryption", "aws:kms" if kms else "AES256"]
        if kms:
            args += ["--ssekms-key-id", kms, "--no-bucket-key-enabled"]
        response = aws.json(args, region=region)
        version = legacy._string(response.get("VersionId"), "published version")
        contract.require(version != "null", "publication requires bucket versioning")
        ref = {"bucket": bucket, "key": key, "region": region, "version_id": version, "sha256": hashlib.sha256(payload).hexdigest()}
        contract.require(read_object(aws, ref, directory) == dict(value), "published object could not be read back exactly")
        return ref
    finally:
        path.unlink(missing_ok=True)


def verify_claim(aws: AWS, handoff: Mapping[str, Any], directory: pathlib.Path) -> None:
    ref = handoff["claim"]
    versions = legacy.exact_object_versions(aws, bucket=ref["bucket"], key=ref["key"], region=ref["region"])
    contract.require(versions == [{"version_id": ref["version_id"], "kind": "version"}], "claim version is absent, replaced, or ambiguous")
    contract.require(read_object(aws, ref, directory) == handoff["claim_body"], "exact claim body does not authorize this handoff")


def revocation_policy(cutoff: str) -> dict[str, Any]:
    contract.timestamp(cutoff)
    return {"Version": "2012-10-17", "Statement": [{"Sid": "RevokeDeploymentSessions", "Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"DateLessThanEquals": {"aws:TokenIssueTime": cutoff}}}]}


def frozen_policy() -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}


def verify_revocation(aws: AWS, handoff: Mapping[str, Any]) -> None:
    rev = handoff["revocation"]
    role_name = rev["role_arn"].split("/")[-1]
    response = aws.json(["iam", "get-role-policy", "--role-name", role_name, "--policy-name", rev["policy_name"]])
    policy = response.get("PolicyDocument")
    if isinstance(policy, str):
        policy = legacy.strict_json_loads(urllib.parse.unquote(policy))
    contract.require(policy == frozen_policy(), "deployment sessions were not unconditionally frozen")
    trust = aws.json(["iam", "get-role", "--role-name", role_name]).get("Role", {}).get("AssumeRolePolicyDocument")
    if isinstance(trust, str):
        trust = legacy.strict_json_loads(urllib.parse.unquote(trust))
    statements = trust.get("Statement", []) if isinstance(trust, Mapping) else []
    matches = [s for s in statements if s.get("Sid") == rev["trust_sid"]]
    principal = {"Federated": f"arn:aws:iam::{rev['role_arn'].split(':')[4]}:oidc-provider/token.actions.githubusercontent.com"}
    contract.require(matches == [{"Sid": rev["trust_sid"], "Effect": "Deny", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": principal}], "deployment OIDC issuer remains usable")
    allows = [s for s in statements if s.get("Effect") == "Allow"]
    contract.require(len(allows) == 1 and allows[0].get("Action") == "sts:AssumeRoleWithWebIdentity" and allows[0].get("Principal") == principal and allows[0].get("Condition") == {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}, "StringLike": {"token.actions.githubusercontent.com:sub": contract.subject(handoff["context"], "deploy", wildcard=True)}}, "deployment trust acquired another authority path")
    for arn in (handoff["roles"]["cleanup"]["arn"], rev["lifecycle_role_arn"]):
        policy = aws.json(["iam", "get-role-policy", "--role-name", arn.split("/")[-1], "--policy-name", rev["policy_name"]]).get("PolicyDocument")
        if isinstance(policy, str):
            policy = legacy.strict_json_loads(urllib.parse.unquote(policy))
        expected_policy = revocation_policy(handoff["observer_sessions_until"]) if arn == handoff["roles"]["cleanup"]["arn"] else frozen_policy()
        contract.require(policy == expected_policy, "earlier cleanup/lifecycle sessions remain usable")
    trust = aws.json(["iam", "get-role", "--role-name", handoff["roles"]["cleanup"]["arn"].split("/")[-1]])["Role"]["AssumeRolePolicyDocument"]
    if isinstance(trust, str):
        trust = legacy.strict_json_loads(urllib.parse.unquote(trust))
    contract.require(trust == {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": principal, "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": handoff["roles"]["cleanup"]["subject"]}, "DateLessThan": {"aws:CurrentTime": handoff["expires_at"]}}}]}, "cleanup OIDC authority is not invocation-isolated")


def verify_phase_identity(aws: AWS, session: Session, h: Mapping[str, Any], phase: str, directory: pathlib.Path) -> None:
    contract.validate_handoff(h, now=dt.datetime.now(dt.timezone.utc), context=contract.execution_context())
    session.require_lifetime(60)
    expected = h["roles"][phase]
    subjects = {expected["subject"]}
    if phase == "quiesce":
        subjects.add(h["roles"]["cleanup"]["subject"])
    contract.require(session.role_arn == expected["arn"] and session.subject in subjects, "phase credentials differ from handoff")
    identity = aws.json(["sts", "get-caller-identity"])
    contract.require(identity.get("Arn") == session.principal_arn, "effective AWS identity differs from issued session")
    policy = aws.json(["iam", "get-role-policy", "--role-name", session.role_arn.split("/")[-1], "--policy-name", "acceptance-boundary"]).get("PolicyDocument")
    if isinstance(policy, str):
        policy = legacy.strict_json_loads(urllib.parse.unquote(policy))
    contract.require(contract.digest(policy) == expected["policy_sha256"], "effective phase policy differs from reviewed handoff")
    if phase in {"observe", "quiesce"}:
        from controller_acceptance_policy import boundary_policy
        contract.require(policy == boundary_policy(dict(h), phase), "phase policy lacks exact closed API/resource denies")
        role = aws.json(["iam", "get-role", "--role-name", session.role_arn.split("/")[-1]])["Role"]
        trust = role["AssumeRolePolicyDocument"]
        if isinstance(trust, str):
            trust = legacy.strict_json_loads(urllib.parse.unquote(trust))
        expected_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": {"Federated": f"arn:aws:iam::{session.role_arn.split(':')[4]}:oidc-provider/token.actions.githubusercontent.com"}, "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": [h['roles']['quiesce']['subject'], h['roles']['cleanup']['subject']] if phase == "quiesce" else [expected['subject']]}, "DateLessThan": {"aws:CurrentTime": h["observer_issuance_until"] if phase == "observe" else h["expires_at"]}}}]}
        contract.require(trust == expected_trust and role.get("MaxSessionDuration") == 3600, "phase trust or session lifetime escaped its drain bound")
        if phase == "observe":
            contract.require(session.expires_at <= contract.timestamp(h["observer_sessions_until"]), "observer session exceeds its quiescence bound")
    verify_claim(aws, h, directory)
    verify_revocation(aws, h)
