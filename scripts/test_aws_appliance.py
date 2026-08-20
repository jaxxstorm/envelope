#!/usr/bin/env python3

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import aws_appliance as appliance  # noqa: E402


VALID_POLICY = {
    "tagOwners": {"tag:envelope-ci": ["group:infra"]},
    "autoApprovers": {
        "routes": {
            "10.10.0.0/16": ["tag:envelope-ci"],
            "10.20.0.0/16": ["tag:envelope-ci"],
        }
    },
    "grants": [
        {"src": ["10.10.0.0/16"], "dst": ["10.20.0.0/16"], "ip": ["*"]},
        {"src": ["10.20.0.0/16"], "dst": ["10.10.0.0/16"], "ip": ["*"]},
    ],
}


def config_document(architecture: str = "amd64", *, expired: bool = False) -> dict:
    expiry = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=-1 if expired else 2)

    def site(region, ami, key, vpc, prefix):
        return {
            "region": region,
            "ami_id": ami,
            "ssm_kms_key_arn": key,
            "azs": {"a": f"{region}a", "b": f"{region}b"},
            "appliance_az_key": "a",
            "vpc_cidr": vpc,
            "public_subnet_cidr": f"{prefix}.40.0/24",
            "appliance_subnet_cidr": f"{prefix}.30.0/24",
            "workload_subnet_cidrs": {"a": f"{prefix}.1.0/24", "b": f"{prefix}.2.0/24"},
            "gwlbe_subnet_cidrs": {"a": f"{prefix}.10.0/24", "b": f"{prefix}.11.0/24"},
            "gwlb_subnet_cidrs": {"a": f"{prefix}.20.0/24", "b": f"{prefix}.21.0/24"},
            "gwlb_return_cidrs": [f"{prefix}.1.0/24"],
            "local_delivery_cidrs": [f"{prefix}.2.0/24"],
        }

    return {
        "run_id": "envelope-fixture",
        "expires_at": expiry.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "architecture": architecture,
        "artifact_manifest": "../../dist/manifest.json",
        "instance_type": "m7g.medium" if architecture == "arm64" else "t3.medium",
        "test_instance_type": "t4g.micro" if architecture == "arm64" else "t3.micro",
        "backend": {
            "bucket": "operator-backend",
            "region": "us-west-2",
            "kms_key_arn": "arn:aws:kms:us-west-2:123456789012:key/backend",
            "state_key": "runs/envelope-fixture/terraform.tfstate",
            "operator_principal_arns": ["arn:aws:iam::123456789012:role/envelope-operator"],
        },
        "sites": {
            "west": site(
                "us-west-2",
                "ami-0123456789abcdef0",
                "arn:aws:kms:us-west-2:123456789012:key/west",
                "10.10.0.0/16",
                "10.10",
            ),
            "east": site(
                "us-east-1",
                "ami-0fedcba9876543210",
                "arn:aws:kms:us-east-1:123456789012:key/east",
                "10.20.0.0/16",
                "10.20",
            ),
        },
        "tailnet": {
            "name": "fixture.example",
            "tag": "tag:envelope-ci",
            "tag_owners": ["group:infra"],
            "snat_subnet_routes": False,
        },
    }


def make_config(tmp: pathlib.Path, architecture: str = "amd64", *, expired: bool = False) -> appliance.RunConfig:
    path = tmp / "config" / "run.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config_document(architecture, expired=expired)))
    return appliance.RunConfig.load(path, enforce_future_expiry=not expired)


def artifact_identity(root: pathlib.Path, architecture: str = "amd64") -> dict:
    return {
        "architecture": architecture,
        "ec2_architecture": appliance.ARCHITECTURES[architecture],
        "sha256": "a" * 64,
        "revision": "b" * 40,
        "version": "fixture.1",
        "go_version": "go1.26.2",
        "manifest_sha256": "c" * 64,
        "manifest_path": str((root / "artifact-manifest.json").resolve()),
        "path": str((root / f"envelope-linux-{architecture}").resolve()),
    }


class ConfigAndPathTest(unittest.TestCase):
    def test_expired_config_loads_only_for_recovery_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root, expired=True)
            self.assertLess(
                dt.datetime.fromisoformat(config.expires_at.replace("Z", "+00:00")),
                dt.datetime.now(dt.timezone.utc),
            )
            with self.assertRaisesRegex(appliance.LifecycleError, "new run"):
                appliance.RunConfig.load(config.path)

    def test_one_config_generates_tailnet_and_all_terraform_network_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            artifact = artifact_identity(root)
            parameters = appliance.intended_ssm_parameters(config, "123456789012")
            values = appliance.terraform_variables(config, artifact, parameters)
            self.assertEqual(values["west_azs"], config.sites["west"]["azs"])
            self.assertEqual(
                values["envelope_remote_tailnet_cidrs"]["west"],
                [config.sites["east"]["workload_subnet_cidrs"][key] for key in ("a", "b")],
            )
            self.assertEqual(config.lane_cidrs["west"], ["10.10.1.0/24", "10.10.2.0/24"])

            document = config_document()
            document["tailnet"]["lane_cidrs"] = {"west": ["10.99.0.0/24"], "east": ["10.98.0.0/24"]}
            path = root / "duplicate.json"
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(appliance.LifecycleError, "only CIDR source"):
                appliance.RunConfig.load(path)
            document = config_document()
            document["network_tfvars"] = "second-source.json"
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(appliance.LifecycleError, "unsupported fields"):
                appliance.RunConfig.load(path)

    def test_relative_artifact_is_resolved_before_cwd_changes(self):
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as other:
            root = pathlib.Path(temporary)
            document = config_document()
            document["artifact_manifest"] = "../artifacts/manifest.json"
            config_path = root / "config" / "run.json"
            config_path.parent.mkdir()
            config_path.write_text(json.dumps(document))
            artifact_dir = root / "artifacts"
            artifact_dir.mkdir()
            binary = artifact_dir / "envelope-linux-amd64"
            binary.write_bytes(b"fixture-go-elf")
            manifest = {
                "schema": 1,
                "version": "fixture.1",
                "revision": "b" * 40,
                "source_dirty": False,
                "go_version": "go1.26.2",
                "artifacts": [
                    {
                        "architecture": "amd64",
                        "ec2_architecture": "x86_64",
                        "file": binary.name,
                        "goos": "linux",
                        "goarch": "amd64",
                        "go_version": "go1.26.2",
                        "vcs_revision": "b" * 40,
                        "vcs_modified": False,
                        "version": "fixture.1",
                        "sha256": "a" * 64,
                    }
                ],
            }
            (artifact_dir / "manifest.json").write_text(json.dumps(manifest))
            config = appliance.RunConfig.load(config_path)
            old_cwd = pathlib.Path.cwd()
            try:
                os.chdir(other)
                with mock.patch.object(
                    appliance,
                    "inspect_artifact",
                    return_value={
                        "architecture": "amd64",
                        "sha256": "a" * 64,
                        "go_version": "go1.26.2",
                        "goos": "linux",
                        "goarch": "amd64",
                        "vcs_revision": "b" * 40,
                        "vcs_modified": False,
                    },
                ):
                    selected = appliance.validate_artifact(config)
                    variables = appliance.terraform_variables(
                        config,
                        selected,
                        appliance.intended_ssm_parameters(config, "123456789012"),
                    )
            finally:
                os.chdir(old_cwd)
            self.assertTrue(pathlib.Path(selected["path"]).is_absolute())
            self.assertEqual(pathlib.Path(selected["path"]), binary.resolve())
            self.assertEqual(pathlib.Path(variables["artifact_path"]), binary.resolve())

    def test_relative_runner_paths_and_oauth_environment_are_normalized(self):
        class CaptureRunner:
            def __init__(self):
                self.calls = []

            def run(inner, args, *, env=None, cwd=None, input_text=None):
                inner.calls.append((args, env, cwd))
                return ""

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            run_dir = root / "relative-run"
            terraform_dir = root / "relative-terraform"
            terraform_dir.mkdir()
            run_dir.mkdir()
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            appliance.ManifestStore(config, BackendAWS(config), run_dir).write(manifest, upload=False)
            runner = CaptureRunner()
            old_cwd = pathlib.Path.cwd()
            try:
                os.chdir(root)
                with mock.patch.object(appliance.BackendValidator, "validate"), mock.patch.dict(
                    os.environ,
                    {"TS_OAUTH_CLIENT_ID": "fixture-client", "TS_OAUTH_CLIENT_SECRET": "fixture-secret"},
                ):
                    backend_file = appliance.terraform_init(
                        config,
                        BackendAWS(config),
                        runner,
                        pathlib.Path("relative-run"),
                        pathlib.Path("relative-terraform"),
                    )
            finally:
                os.chdir(old_cwd)
            args, env, cwd = runner.calls[0]
            self.assertTrue(backend_file.is_absolute())
            self.assertTrue(pathlib.Path(env["TF_DATA_DIR"]).is_absolute())
            self.assertTrue(cwd.is_absolute())
            self.assertIn(f"-backend-config={backend_file}", args)
            self.assertNotIn("TS_OAUTH_CLIENT_ID", env)
            self.assertNotIn("TS_OAUTH_CLIENT_SECRET", env)
            with mock.patch.dict(
                os.environ,
                {"TS_OAUTH_CLIENT_ID": "fixture-client", "TS_OAUTH_CLIENT_SECRET": "fixture-secret"},
            ):
                appliance.AwsCLI(runner, config.oauth_environment_names).call(["sts", "get-caller-identity"])
            aws_env = runner.calls[-1][1]
            self.assertNotIn("TS_OAUTH_CLIENT_ID", aws_env)
            self.assertNotIn("TS_OAUTH_CLIENT_SECRET", aws_env)

    def test_subprocess_runner_strips_configured_oauth_names_defensively(self):
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.dict(os.environ, {"CUSTOM_TS_ID": "id", "CUSTOM_TS_SECRET": "secret"}), mock.patch(
            "subprocess.run", return_value=completed
        ) as run:
            appliance.SubprocessRunner(("CUSTOM_TS_ID", "CUSTOM_TS_SECRET")).run(["fixture"])
        child_env = run.call_args.kwargs["env"]
        self.assertNotIn("CUSTOM_TS_ID", child_env)
        self.assertNotIn("CUSTOM_TS_SECRET", child_env)

    def test_apply_boundary_is_durable_before_the_terraform_child_runs(self):
        class ManifestAWS:
            def json(self, args, *, region=None):
                if args[1] == "put-object":
                    return {}
                raise AssertionError(args)

        class FailingRunner:
            def __init__(self):
                self.calls = []

            def run(inner, args, *, env=None, cwd=None, input_text=None):
                inner.calls.append((args, env, cwd))
                if len(args) > 1 and args[1] == "apply":
                    raise appliance.LifecycleError("injected runner loss after apply boundary")
                return ""

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            terraform_dir = root / "terraform"
            terraform_dir.mkdir()
            config = make_config(root)
            aws = ManifestAWS()
            store = appliance.ManifestStore(config, aws, root / "run")
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            plan = store.run_dir / "apply.tfplan"
            store.run_dir.mkdir(parents=True)
            plan.write_bytes(b"reviewed-plan")
            manifest["saved_plan"] = {
                "path": str(plan.resolve()),
                "sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
                "replacement": None,
            }
            manifest["phase"] = "planned"
            store.write(manifest)
            runner = FailingRunner()
            with mock.patch.object(appliance.BackendValidator, "validate"):
                with self.assertRaisesRegex(appliance.LifecycleError, "runner loss"):
                    appliance.terraform_apply(config, aws, runner, store.run_dir, terraform_dir, plan)
            persisted = store.load_local()
            self.assertEqual(persisted["phase"], "apply_started")
            self.assertTrue(persisted["tailnet"]["nodes_expected"])

    def test_no_drift_runner_uses_durable_inputs_and_maps_exit_two_to_drift(self):
        class CaptureRunner:
            def __init__(self, drift=False):
                self.calls = []
                self.drift = drift

            def run(inner, args, *, env=None, cwd=None, input_text=None):
                inner.calls.append((args, env, cwd))
                if len(args) > 1 and args[1] == "plan" and inner.drift:
                    raise appliance.CommandError(args, 2, "fixture drift")
                return ""

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            terraform_dir = root / "terraform"
            terraform_dir.mkdir()
            store = appliance.ManifestStore(config, BackendAWS(config), root / "run")
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            store.write(manifest, upload=False)
            for drift in (False, True):
                with self.subTest(drift=drift):
                    runner = CaptureRunner(drift)
                    with mock.patch.object(appliance.BackendValidator, "validate"), mock.patch.object(
                        appliance, "artifact_for_recovery", return_value=artifact_identity(root)
                    ), mock.patch.dict(
                        os.environ,
                        {"TS_OAUTH_CLIENT_ID": "fixture-client", "TS_OAUTH_CLIENT_SECRET": "fixture-secret"},
                    ):
                        if drift:
                            with self.assertRaisesRegex(appliance.LifecycleError, "detected Terraform changes"):
                                appliance.terraform_verify_no_drift(
                                    config, BackendAWS(config), runner, store.run_dir, terraform_dir
                                )
                        else:
                            appliance.terraform_verify_no_drift(
                                config, BackendAWS(config), runner, store.run_dir, terraform_dir
                            )
                    plan_args, plan_env, plan_cwd = next(
                        call for call in runner.calls if len(call[0]) > 1 and call[0][1] == "plan"
                    )
                    self.assertIn("-detailed-exitcode", plan_args)
                    variable_arg = next(value for value in plan_args if value.startswith("-var-file="))
                    self.assertTrue(pathlib.Path(variable_arg.split("=", 1)[1]).is_absolute())
                    self.assertTrue(plan_cwd.is_absolute())
                    self.assertNotIn("TS_OAUTH_CLIENT_ID", plan_env)
                    self.assertNotIn("TS_OAUTH_CLIENT_SECRET", plan_env)


class FakeHTTP:
    def __init__(self, policy: dict | None = None):
        self.policy = policy or VALID_POLICY
        self.requests: list[tuple[str, str, bytes | None]] = []
        self.devices = {"devices": []}
        self.urls: list[str] = []

    def request(self, method: str, url: str, *, headers=None, body=None):
        self.urls.append(url)
        path = urllib.parse.urlparse(url).path
        self.requests.append((method, path, body))
        if path.endswith("/oauth/token"):
            return 200, json.dumps({"access_token": "fixture-bearer"}).encode()
        if path.endswith("/acl"):
            return 200, json.dumps(self.policy).encode()
        if path.endswith("/devices") and method == "GET":
            return 200, json.dumps(self.devices).encode()
        if path.endswith("/keys") and method == "POST":
            return 200, json.dumps({"id": "key-fixture-id", "key": "fixture-auth-material"}).encode()
        if path.endswith("/keys") and method == "GET":
            return 200, b'{"keys":[]}'
        if method == "DELETE":
            return 200, b"{}"
        return 404, b'{"message":"fixture route missing"}'


class BackendAWS:
    def __init__(self, config: appliance.RunConfig):
        self.config = config
        self.versioning = "Enabled"
        self.algorithm = "aws:kms"
        self.key = config.backend["kms_key_arn"]
        self.public = True
        self.existing: set[str] = set()
        self.versions: dict[str, list[dict[str, str]]] = {}
        self.policy_public = False
        self.key_enabled = True
        self.key_manager = "CUSTOMER"
        principal = config.backend["operator_principal_arns"][0]
        bucket_arn = f"arn:aws:s3:::{config.backend['bucket']}"
        object_actions = {
            f"{bucket_arn}/{config.backend['state_key']}": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObjectVersion",
            ],
            f"{bucket_arn}/{config.lock_key}": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:DeleteObjectVersion",
            ],
            f"{bucket_arn}/{config.manifest_key}": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:PutObjectTagging",
                "s3:DeleteObjectVersion",
            ],
        }
        self.bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [bucket_arn, f"{bucket_arn}/*"],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": list(appliance.BACKEND_BUCKET_ACTIONS),
                    "Resource": bucket_arn,
                },
                *[
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": principal},
                        "Action": actions,
                        "Resource": object_arn,
                    }
                    for object_arn, actions in object_actions.items()
                ],
            ],
        }
        self.key_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": list(appliance.BACKEND_KMS_ACTIONS),
                    "Resource": self.key,
                }
            ],
        }

    def json(self, args, *, region=None):
        operation = args[1]
        if operation == "head-bucket":
            return {}
        if operation == "get-bucket-location":
            return {"LocationConstraint": self.config.backend["region"]}
        if operation == "get-bucket-versioning":
            return {"Status": self.versioning}
        if operation == "get-bucket-encryption":
            return {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": self.algorithm,
                                "KMSMasterKeyID": self.key,
                            }
                        }
                    ]
                }
            }
        if operation == "get-public-access-block":
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": self.public,
                    "IgnorePublicAcls": self.public,
                    "BlockPublicPolicy": self.public,
                    "RestrictPublicBuckets": self.public,
                }
            }
        if operation == "get-bucket-policy-status":
            return {"PolicyStatus": {"IsPublic": self.policy_public}}
        if operation == "get-bucket-policy":
            return {"Policy": json.dumps(self.bucket_policy)}
        if operation == "describe-key":
            return {
                "KeyMetadata": {
                    "Arn": self.key,
                    "Enabled": self.key_enabled,
                    "KeyUsage": "ENCRYPT_DECRYPT",
                    "KeySpec": "SYMMETRIC_DEFAULT",
                    "KeyManager": self.key_manager,
                }
            }
        if operation == "get-key-policy":
            return {"Policy": json.dumps(self.key_policy)}
        if operation == "list-object-versions":
            key = args[args.index("--prefix") + 1]
            return {"Versions": self.versions.get(key, []), "DeleteMarkers": []}
        if operation == "put-object":
            return {"VersionId": "manifest-version"}
        raise AssertionError(args)

    def object_exists(self, bucket, key, region):
        return key in self.existing


class MetadataAWS:
    def __init__(self, config: appliance.RunConfig):
        self.config = config
        self.expected = appliance.ARCHITECTURES[config.architecture]
        self.image_overrides: dict[str, object] = {}
        self.type_architectures = [self.expected]

    def json(self, args, *, region=None):
        operation = args[1]
        if operation == "describe-images":
            image_id = args[3]
            image = {
                "ImageId": image_id,
                "Architecture": self.expected,
                "State": "available",
                "RootDeviceType": "ebs",
                "VirtualizationType": "hvm",
                "Name": "al2023-ami-2023.8.20260818.0-kernel-6.1-x86_64",
            }
            image.update(self.image_overrides)
            return {"Images": [image]}
        if operation == "describe-instance-types":
            return {
                "InstanceTypes": [
                    {
                        "InstanceType": selected,
                        "ProcessorInfo": {"SupportedArchitectures": self.type_architectures},
                    }
                    for selected in args[3:]
                ]
            }
        raise AssertionError(args)


class PolicyAndAdapterTest(unittest.TestCase):
    def test_hujson_comments_unquoted_keys_and_trailing_commas(self):
        policy = appliance.parse_hujson(
            """
            {
              // fixture comment
              tagOwners: {"tag:envelope-ci": ["group:infra",],},
              autoApprovers: {routes: {"10.10.0.0/16": ["tag:envelope-ci"]}},
              grants: [],
            }
            """
        )
        self.assertEqual(policy["tagOwners"]["tag:envelope-ci"], ["group:infra"])

    def test_policy_contract_and_failure_matrix(self):
        arguments = {
            "tag": "tag:envelope-ci",
            "tag_owners": ["group:infra"],
            "advertised_routes": ["10.10.1.0/24", "10.20.1.0/24"],
            "lane_cidrs": {"west": ["10.10.1.0/24"], "east": ["10.20.1.0/24"]},
            "snat_subnet_routes": False,
        }
        appliance.validate_tailnet_policy(copy.deepcopy(VALID_POLICY), **arguments)
        cases = {
            "tag owner": lambda value: value["tagOwners"].clear(),
            "auto approval": lambda value: value["autoApprovers"]["routes"].pop("10.20.0.0/16"),
            "grant": lambda value: value["grants"].pop(),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                policy = copy.deepcopy(VALID_POLICY)
                mutate(policy)
                with self.assertRaises(appliance.LifecycleError):
                    appliance.validate_tailnet_policy(policy, **arguments)
        with self.assertRaisesRegex(appliance.LifecycleError, "SNAT"):
            appliance.validate_tailnet_policy(copy.deepcopy(VALID_POLICY), **{**arguments, "snat_subnet_routes": True})

    def test_oauth_key_shape_and_lifecycle_are_fixture_testable(self):
        transport = FakeHTTP()
        api = appliance.TailscaleAPI("fixture.example", "client", "fixture-secret", transport)
        self.assertEqual(api.list_devices(), [])
        self.assertTrue(any(urllib.parse.urlparse(url).query == "fields=all" for url in transport.urls))
        key_id, key = api.create_auth_key("tag:envelope-ci", "fixture", 1800)
        self.assertEqual((key_id, key), ("key-fixture-id", "fixture-auth-material"))
        api.revoke_auth_key(key_id)
        create = next(json.loads(body) for method, path, body in transport.requests if method == "POST" and path.endswith("/keys"))
        capabilities = create["capabilities"]["devices"]["create"]
        self.assertEqual(
            capabilities,
            {"reusable": True, "ephemeral": True, "preauthorized": True, "tags": ["tag:envelope-ci"]},
        )
        self.assertEqual(create["expirySeconds"], 1800)

    def test_delete_accepts_every_success_body_shape_and_bounds_failures(self):
        class DeleteHTTP:
            def __init__(self, status, body):
                self.status = status
                self.body = body

            def request(self, method, url, *, headers=None, body=None):
                if urllib.parse.urlparse(url).path.endswith("/oauth/token"):
                    return 200, b'{"access_token":"fixture-bearer"}'
                if method == "DELETE":
                    return self.status, self.body
                raise AssertionError((method, url))

        responses = (
            (200, b""),
            (200, b"{}"),
            (200, b"[]"),
            (202, b"null"),
            (202, b"plain text"),
            (204, b""),
            (404, b"[]"),
        )
        for operation in ("key", "device"):
            for status, body in responses:
                with self.subTest(operation=operation, status=status, body=body):
                    api = appliance.TailscaleAPI(
                        "fixture.example", "client", "fixture-secret", DeleteHTTP(status, body)
                    )
                    if operation == "key":
                        api.revoke_auth_key("key-fixture")
                    else:
                        api.delete_device("device-fixture")

        secret = "tskey-" + "auth-fixture123456789"
        api = appliance.TailscaleAPI(
            "fixture.example",
            "client",
            "fixture-secret",
            DeleteHTTP(500, (f'{{"message":"auth_key={secret}"}}' + "x" * 2048).encode()),
        )
        with self.assertRaises(appliance.LifecycleError) as raised:
            api.revoke_auth_key("key-fixture")
        self.assertNotIn(secret, str(raised.exception))
        self.assertLess(len(str(raised.exception)), 700)

    def test_non_object_delete_success_is_followed_by_confirmed_absence(self):
        class StatefulHTTP:
            def __init__(self):
                self.keys = [{"id": "key-fixture", "description": "fixture"}]
                self.devices = [{"id": "device-fixture", "hostname": "fixture"}]

            def request(self, method, url, *, headers=None, body=None):
                path = urllib.parse.urlparse(url).path
                if path.endswith("/oauth/token"):
                    return 200, b'{"access_token":"fixture-bearer"}'
                if path.endswith("/keys") and method == "GET":
                    return 200, json.dumps({"keys": self.keys}).encode()
                if path.endswith("/devices") and method == "GET":
                    return 200, json.dumps({"devices": self.devices}).encode()
                if "/keys/" in path and method == "DELETE":
                    self.keys = []
                    return 200, b"[]"
                if path.endswith("/device-fixture") and method == "DELETE":
                    self.devices = []
                    return 200, b"null"
                raise AssertionError((method, url))

        api = appliance.TailscaleAPI("fixture.example", "client", "fixture-secret", StatefulHTTP())
        self.assertEqual(len(api.list_auth_keys()), 1)
        self.assertEqual(len(api.list_devices()), 1)
        api.revoke_auth_key("key-fixture")
        api.delete_device("device-fixture")
        self.assertEqual(api.list_auth_keys(), [])
        self.assertEqual(api.list_devices(), [])


class SecurityAndBackendTest(unittest.TestCase):
    def test_redaction(self):
        aws_key = "AKIA" + "ABCDEFGHIJKLMNOP"
        value = f"auth_key=fixture-value token: bearer-value access key {aws_key} tskey-auth-abc123"
        result = appliance.redact(value)
        for prohibited in ("fixture-value", "bearer-value", aws_key, "tskey-auth-abc123"):
            self.assertNotIn(prohibited, result)

    def test_backend_requires_versioning_kms_public_block_and_unique_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            aws = BackendAWS(config)
            validator = appliance.BackendValidator(aws)
            validator.validate(config, require_empty=True)
            mutations = (
                ("versioning", "Suspended"),
                ("algorithm", "AES256"),
                ("key", "arn:aws:kms:us-west-2:123456789012:key/wrong"),
                ("public", False),
                ("policy_public", True),
                ("key_enabled", False),
            )
            for field, value in mutations:
                with self.subTest(field=field):
                    candidate = BackendAWS(config)
                    setattr(candidate, field, value)
                    with self.assertRaises(appliance.LifecycleError):
                        appliance.BackendValidator(candidate).validate(config, require_empty=True)
            aws.versions[config.backend["state_key"]] = [
                {"Key": config.backend["state_key"], "VersionId": "historical"}
            ]
            with self.assertRaisesRegex(appliance.LifecycleError, "historical"):
                validator.validate(config, require_empty=True)
            denied = BackendAWS(config)
            denied.bucket_policy["Statement"] = denied.bucket_policy["Statement"][:1]
            with self.assertRaisesRegex(appliance.LifecycleError, "backend policy omits"):
                appliance.BackendValidator(denied).validate(config, require_empty=True)

    def test_backend_policy_rejects_each_omitted_lifecycle_action(self):
        def omit_action(policy, action):
            removed = False
            for statement in policy["Statement"]:
                actions = statement.get("Action")
                if isinstance(actions, list) and action in actions:
                    statement["Action"] = [value for value in actions if value != action]
                    removed = True
            self.assertTrue(removed, action)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            baseline = BackendAWS(config)
            s3_actions = {
                str(action)
                for statement in baseline.bucket_policy["Statement"]
                for action in (statement.get("Action") if isinstance(statement.get("Action"), list) else [])
                if str(action).startswith("s3:") and action != "s3:*"
            }
            for action in sorted(s3_actions):
                with self.subTest(action=action):
                    candidate = BackendAWS(config)
                    omit_action(candidate.bucket_policy, action)
                    with self.assertRaisesRegex(appliance.LifecycleError, re.escape(action)):
                        appliance.BackendValidator(candidate).validate(config, require_empty=True)
            for action in appliance.BACKEND_KMS_ACTIONS:
                with self.subTest(action=action):
                    candidate = BackendAWS(config)
                    omit_action(candidate.key_policy, action)
                    with self.assertRaisesRegex(appliance.LifecycleError, re.escape(action)):
                        appliance.BackendValidator(candidate).validate(config, require_empty=True)

    def test_backend_configuration_requires_encryption_and_lockfile(self):
        with tempfile.TemporaryDirectory() as temporary:
            text = appliance.backend_config_text(make_config(pathlib.Path(temporary)))
        self.assertIn('key = "runs/envelope-fixture/terraform.tfstate"', text)
        self.assertIn("encrypt = true", text)
        self.assertIn("use_lockfile = true", text)
        self.assertNotIn("access_key", text)
        self.assertNotIn("secret_key", text)

    def test_manifest_is_secret_free_protected_and_durable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            aws = BackendAWS(config)
            artifact = artifact_identity(root)
            manifest = appliance.new_manifest(config, artifact, "123456789012")
            store = appliance.ManifestStore(config, aws, root / "run")
            store.write(manifest)
            self.assertEqual(stat.S_IMODE(store.path.stat().st_mode), 0o600)
            serialized = store.path.read_text()
            self.assertNotIn("auth-material", serialized)
            self.assertNotIn("oauth", serialized.lower())
            appliance.validate_manifest(json.loads(serialized), config)
            self.assertEqual(set(manifest["terraform_variables"]), set(appliance.terraform_variables(config, artifact, manifest["ssm_parameters"])))
            self.assertEqual([value["created"] for value in manifest["ssm_parameters"]], [False, False])

    def test_residual_allowlist_never_accepts_shared_backend_and_enforces_janitor_ttl(self):
        class UnusedAWS:
            def json(self, *args, **kwargs):
                raise AssertionError("validation must fail before AWS deletion")

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            backend = [{"arn": "arn:aws:s3:::operator-backend", "region": "us-west-2"}]
            with self.assertRaisesRegex(appliance.LifecycleError, "shared backend"):
                appliance.remove_owned_residuals(
                    config,
                    UnusedAWS(),
                    backend,
                    dry_run=False,
                    allow_unexpired=True,
                    sleep=lambda _: None,
                )
            with self.assertRaisesRegex(appliance.LifecycleError, "TTL"):
                appliance.remove_owned_residuals(
                    config,
                    UnusedAWS(),
                    [],
                    dry_run=False,
                    allow_unexpired=False,
                    sleep=lambda _: None,
                )
            expired = make_config(root / "expired", expired=True)
            self.assertEqual(
                appliance.remove_owned_residuals(
                    expired,
                    UnusedAWS(),
                    [],
                    dry_run=False,
                    allow_unexpired=False,
                    sleep=lambda _: None,
                ),
                [],
            )

    def test_allowlisted_owned_residual_is_removed_and_reaudited(self):
        class ResidualAWS:
            def __init__(self):
                self.terminated = []

            def json(self, args, *, region=None):
                if args[1] == "terminate-instances":
                    self.terminated.append(args[-1])
                    return {}
                if args[1] == "get-resources":
                    return {"ResourceTagMappingList": []}
                raise AssertionError(args)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            aws = ResidualAWS()
            resource = {
                "arn": "arn:aws:ec2:us-west-2:123456789012:instance/i-ownedfixture",
                "region": "us-west-2",
            }
            removed = appliance.remove_owned_residuals(
                config,
                aws,
                [resource],
                dry_run=False,
                allow_unexpired=True,
                sleep=lambda _: None,
            )
            self.assertEqual(removed, [resource["arn"]])
            self.assertEqual(aws.terminated, ["i-ownedfixture"])
            with self.assertRaisesRegex(appliance.LifecycleError, "allowlist"):
                appliance.remove_owned_residuals(
                    config,
                    aws,
                    [{"arn": "arn:aws:kms:us-west-2:123456789012:key/shared", "region": "us-west-2"}],
                    dry_run=False,
                    allow_unexpired=True,
                    sleep=lambda _: None,
                )

    def test_residual_recovery_uses_dependency_order_and_bounded_async_window(self):
        class UnusedAWS:
            pass

        resources = [
            {"arn": "arn:aws:ec2:us-west-2:123456789012:vpc/vpc-fixture", "region": "us-west-2"},
            {"arn": "arn:aws:s3:::run-artifact-fixture", "region": "us-west-2"},
            {"arn": "arn:aws:iam::123456789012:role/run-role", "region": "us-west-2"},
            {"arn": "arn:aws:ec2:us-west-2:123456789012:subnet/subnet-fixture", "region": "us-west-2"},
            {
                "arn": "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/gwy/run/id",
                "region": "us-west-2",
            },
            {
                "arn": "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint/vpce-fixture",
                "region": "us-west-2",
            },
            {"arn": "arn:aws:ec2:us-west-2:123456789012:instance/i-fixture", "region": "us-west-2"},
        ]
        order = []
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            with mock.patch.object(
                appliance,
                "delete_owned_resource",
                side_effect=lambda aws, resource: order.append(appliance.owned_resource_kind(resource["arn"])[0]),
            ), mock.patch.object(appliance, "audit_run_resources", return_value=[]):
                appliance.remove_owned_residuals(
                    config,
                    UnusedAWS(),
                    resources,
                    dry_run=False,
                    allow_unexpired=True,
                    sleep=lambda _: None,
                )
        self.assertEqual(
            order,
            ["instance", "vpc-endpoint", "load-balancer", "subnet", "role", "s3-bucket", "vpc"],
        )
        self.assertEqual(appliance.RESIDUAL_CLEANUP_TIMEOUT_SECONDS, 15 * 60)
        self.assertLessEqual(
            appliance.RESIDUAL_CLEANUP_INITIAL_BACKOFF_SECONDS,
            appliance.RESIDUAL_CLEANUP_MAX_BACKOFF_SECONDS,
        )

    def test_authoritative_liveness_covers_every_allowlisted_resource_kind(self):
        cases = (
            ("arn:aws:s3:::run-artifact", "head-bucket", {}),
            (
                "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/gwy/run/id",
                "describe-load-balancers",
                {"LoadBalancers": [{"LoadBalancerArn": "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/gwy/run/id"}]},
            ),
            (
                "arn:aws:elasticloadbalancing:us-west-2:123456789012:listener/gwy/run/id/listener",
                "describe-listeners",
                {"Listeners": [{"ListenerArn": "arn:aws:elasticloadbalancing:us-west-2:123456789012:listener/gwy/run/id/listener"}]},
            ),
            (
                "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/run/id",
                "describe-target-groups",
                {"TargetGroups": [{"TargetGroupArn": "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/run/id"}]},
            ),
            (
                "arn:aws:iam::123456789012:instance-profile/run-profile",
                "get-instance-profile",
                {"InstanceProfile": {"InstanceProfileName": "run-profile"}},
            ),
            ("arn:aws:iam::123456789012:role/run-role", "get-role", {"Role": {"RoleName": "run-role"}}),
            (
                "arn:aws:ssm:us-west-2:123456789012:parameter/envelope-fixture/tailscale-auth",
                "describe-parameters",
                {"Parameters": [{"Name": "/envelope-fixture/tailscale-auth"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:instance/i-live",
                "describe-instances",
                {"Reservations": [{"Instances": [{"InstanceId": "i-live", "State": {"Name": "running"}}]}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:volume/vol-live",
                "describe-volumes",
                {"Volumes": [{"VolumeId": "vol-live", "State": "available"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint/vpce-live",
                "describe-vpc-endpoints",
                {"VpcEndpoints": [{"VpcEndpointId": "vpce-live", "State": "available"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint-service/vpce-svc-live",
                "describe-vpc-endpoint-service-configurations",
                {"ServiceConfigurations": [{"ServiceId": "vpce-svc-live", "ServiceState": "Available"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:natgateway/nat-live",
                "describe-nat-gateways",
                {"NatGateways": [{"NatGatewayId": "nat-live", "State": "available"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:elastic-ip/eipalloc-live",
                "describe-addresses",
                {"Addresses": [{"AllocationId": "eipalloc-live"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:internet-gateway/igw-live",
                "describe-internet-gateways",
                {"InternetGateways": [{"InternetGatewayId": "igw-live"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:route-table/rtb-live",
                "describe-route-tables",
                {"RouteTables": [{"RouteTableId": "rtb-live"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:subnet/subnet-live",
                "describe-subnets",
                {"Subnets": [{"SubnetId": "subnet-live"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:security-group/sg-live",
                "describe-security-groups",
                {"SecurityGroups": [{"GroupId": "sg-live"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:network-interface/eni-live",
                "describe-network-interfaces",
                {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-live"}]},
            ),
            (
                "arn:aws:ec2:us-west-2:123456789012:vpc/vpc-live",
                "describe-vpcs",
                {"Vpcs": [{"VpcId": "vpc-live"}]},
            ),
        )

        class DescribeAWS:
            def __init__(self, operation, response):
                self.operation = operation
                self.response = response
                self.calls = []

            def json(self, args, *, region=None):
                self.calls.append((args, region))
                self.assert_operation(args[1])
                return self.response

            def assert_operation(self, operation):
                if operation != self.operation:
                    raise AssertionError((operation, self.operation))

        self.assertEqual(len(cases), len(appliance.RESIDUAL_DELETE_PRIORITY))
        for arn, operation, response in cases:
            with self.subTest(arn=arn):
                aws = DescribeAWS(operation, response)
                self.assertTrue(appliance.owned_resource_is_live(aws, {"arn": arn, "region": "us-west-2"}))
                self.assertIn(appliance.owned_resource_kind(arn)[1], " ".join(aws.calls[0][0]))

        volume = {"arn": "arn:aws:ec2:us-west-2:123456789012:volume/vol-live", "region": "us-west-2"}
        with self.assertRaisesRegex(appliance.LifecycleError, "exact requested identity"):
            appliance.owned_resource_is_live(
                DescribeAWS("describe-volumes", {"Volumes": [{"VolumeId": "vol-other", "State": "available"}]}),
                volume,
            )
        denied = mock.Mock()
        denied.json.side_effect = appliance.CommandError(["aws", "describe-volumes"], 255, "AccessDenied")
        with self.assertRaises(appliance.CommandError):
            appliance.owned_resource_is_live(denied, volume)

    def test_tag_tombstones_are_filtered_before_cleanup_without_delete_retries(self):
        tombstones = [
            {"arn": "arn:aws:ec2:us-west-2:123456789012:instance/i-terminated", "region": "us-west-2"},
            {"arn": "arn:aws:ec2:us-west-2:123456789012:natgateway/nat-deleted", "region": "us-west-2"},
            {"arn": "arn:aws:ec2:us-west-2:123456789012:volume/vol-absent", "region": "us-west-2"},
            {"arn": "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint/vpce-empty", "region": "us-west-2"},
            {"arn": "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint/vpce-absent", "region": "us-west-2"},
            {
                "arn": "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint-service/vpce-svc-absent",
                "region": "us-west-2",
            },
        ]

        class TombstoneAWS:
            def __init__(self, config):
                self.config = config
                self.delete_calls = []

            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "get-resources":
                    if region != self.config.sites["west"]["region"]:
                        return {"ResourceTagMappingList": []}
                    return {
                        "ResourceTagMappingList": [
                            {
                                "ResourceARN": resource["arn"],
                                "Tags": [
                                    {"Key": "EnvelopeRun", "Value": self.config.run_id},
                                    {"Key": "ExpiresAt", "Value": self.config.expires_at},
                                ],
                            }
                            for resource in tombstones
                        ]
                    }
                if operation == "describe-instances":
                    return {
                        "Reservations": [
                            {"Instances": [{"InstanceId": "i-terminated", "State": {"Name": "terminated"}}]}
                        ]
                    }
                if operation == "describe-nat-gateways":
                    return {"NatGateways": [{"NatGatewayId": "nat-deleted", "State": "deleted"}]}
                if operation == "describe-volumes":
                    raise appliance.CommandError(args, 255, "InvalidVolume.NotFound: fixture tombstone")
                if operation == "describe-vpc-endpoints":
                    endpoint_id = args[-1]
                    if endpoint_id == "vpce-empty":
                        return {"VpcEndpoints": []}
                    raise appliance.CommandError(args, 255, "InvalidVpcEndpointId.NotFound: fixture tombstone")
                if operation == "describe-vpc-endpoint-service-configurations":
                    raise appliance.CommandError(
                        args, 255, "InvalidVpcEndpointServiceId.NotFound: fixture tombstone"
                    )
                if operation.startswith(("delete", "terminate", "release")):
                    self.delete_calls.append(operation)
                    return {}
                raise AssertionError(args)

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            aws = TombstoneAWS(config)
            residuals = appliance.audit_run_resources(config, aws)
            self.assertEqual(residuals, [])
            self.assertEqual(
                appliance.remove_owned_residuals(
                    config,
                    aws,
                    residuals,
                    dry_run=False,
                    allow_unexpired=True,
                    sleep=lambda _: self.fail("filtered tombstones must not retry"),
                ),
                [],
            )
            self.assertEqual(aws.delete_calls, [])
            for state in ("deleted", "failed"):
                with self.subTest(nat_state=state):
                    response = {"NatGateways": [{"NatGatewayId": "nat-deleted", "State": state}]}
                    with mock.patch.object(aws, "json", return_value=response):
                        self.assertFalse(appliance.owned_resource_is_live(aws, tombstones[1]))

    def test_residual_dependencies_are_reaudited_retried_and_eventually_absent(self):
        class Clock:
            def __init__(self):
                self.now = 0.0
                self.sleeps = []

            def monotonic(self):
                return self.now

            def sleep(self, seconds):
                self.sleeps.append(seconds)
                self.now += seconds

        class DependencyAWS:
            def __init__(self, config, operations):
                self.config = config
                self.operations = operations
                self.remaining = {value[0]: value[1] for value in operations.values()}
                self.calls = {operation: 0 for operation in operations}

            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "get-resources":
                    if region != self.config.sites["west"]["region"]:
                        return {"ResourceTagMappingList": []}
                    return {
                        "ResourceTagMappingList": [
                            {
                                "ResourceARN": resource["arn"],
                                "Tags": [
                                    {"Key": "EnvelopeRun", "Value": self.config.run_id},
                                    {"Key": "ExpiresAt", "Value": self.config.expires_at},
                                ],
                            }
                            for resource in self.remaining.values()
                        ]
                    }
                describes = {
                    "describe-vpc-endpoints": (
                        "delete-vpc-endpoints",
                        "VpcEndpoints",
                        "VpcEndpointId",
                        "State",
                        "available",
                    ),
                    "describe-vpc-endpoint-service-configurations": (
                        "delete-vpc-endpoint-service-configurations",
                        "ServiceConfigurations",
                        "ServiceId",
                        "ServiceState",
                        "Available",
                    ),
                    "describe-nat-gateways": (
                        "delete-nat-gateway",
                        "NatGateways",
                        "NatGatewayId",
                        "State",
                        "available",
                    ),
                    "describe-addresses": ("release-address", "Addresses", "AllocationId", None, None),
                }
                if operation in describes:
                    delete_operation, collection, identity_field, state_field, state = describes[operation]
                    arn = self.operations[delete_operation][0]
                    if arn not in self.remaining:
                        return {collection: []}
                    value = {identity_field: arn.rsplit("/", 1)[1]}
                    if state_field is not None:
                        value[state_field] = state
                    return {collection: [value]}
                arn, resource, error_code = self.operations[operation]
                self.calls[operation] += 1
                if self.calls[operation] == 1:
                    raise appliance.CommandError(
                        ["aws", operation],
                        255,
                        f"An error occurred ({error_code}) while deleting an exact run resource",
                    )
                self.remaining.pop(arn)
                return {}

        cases = {
            "gwlbe and endpoint service": {
                "delete-vpc-endpoints": (
                    "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint/vpce-fixture",
                    {
                        "arn": "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint/vpce-fixture",
                        "region": "us-west-2",
                    },
                    "OperationNotPermitted",
                ),
                "delete-vpc-endpoint-service-configurations": (
                    "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint-service/vpce-svc-fixture",
                    {
                        "arn": "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint-service/vpce-svc-fixture",
                        "region": "us-west-2",
                    },
                    "ExistingVpcEndpointConnections",
                ),
            },
            "nat and eip": {
                "delete-nat-gateway": (
                    "arn:aws:ec2:us-west-2:123456789012:natgateway/nat-fixture",
                    {
                        "arn": "arn:aws:ec2:us-west-2:123456789012:natgateway/nat-fixture",
                        "region": "us-west-2",
                    },
                    "DependencyViolation",
                ),
                "release-address": (
                    "arn:aws:ec2:us-west-2:123456789012:elastic-ip/eipalloc-fixture",
                    {
                        "arn": "arn:aws:ec2:us-west-2:123456789012:elastic-ip/eipalloc-fixture",
                        "region": "us-west-2",
                    },
                    "InvalidIPAddress.InUse",
                ),
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            for name, operations in cases.items():
                with self.subTest(name=name):
                    clock = Clock()
                    aws = DependencyAWS(config, operations)
                    resources = [value[1] for value in operations.values()]
                    removed = appliance.remove_owned_residuals(
                        config,
                        aws,
                        resources,
                        dry_run=False,
                        allow_unexpired=True,
                        sleep=clock.sleep,
                        monotonic=clock.monotonic,
                    )
                    self.assertEqual(set(removed), {resource["arn"] for resource in resources})
                    self.assertEqual(aws.calls, {operation: 2 for operation in operations})
                    self.assertEqual(aws.remaining, {})
                    self.assertEqual(appliance.audit_run_resources(config, aws), [])
                    self.assertEqual(clock.sleeps, [appliance.RESIDUAL_CLEANUP_INITIAL_BACKOFF_SECONDS])

    def test_terminal_auth_failure_does_not_block_independent_residual_cleanup(self):
        resources = [
            {"arn": "arn:aws:ec2:us-west-2:123456789012:instance/i-denied", "region": "us-west-2"},
            {"arn": "arn:aws:ec2:us-west-2:123456789012:vpc-endpoint/vpce-removed", "region": "us-west-2"},
        ]
        attempted = []

        def delete(_aws, resource):
            attempted.append(resource["arn"])
            if resource["arn"].endswith("i-denied"):
                raise appliance.CommandError(["aws", "delete"], 255, "AccessDenied: fixture terminal denial")

        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            with mock.patch.object(appliance, "delete_owned_resource", side_effect=delete), mock.patch.object(
                appliance, "audit_run_resources", return_value=[resources[0]]
            ):
                with self.assertRaisesRegex(appliance.LifecycleError, "AccessDenied"):
                    appliance.remove_owned_residuals(
                        config,
                        object(),
                        resources,
                        dry_run=False,
                        allow_unexpired=True,
                        sleep=lambda _: self.fail("terminal-only residual must not back off"),
                    )
        self.assertEqual(attempted, [resource["arn"] for resource in resources])


class MetadataTest(unittest.TestCase):
    def test_amd64_and_arm64_mapping(self):
        with tempfile.TemporaryDirectory() as temporary:
            for architecture in ("amd64", "arm64"):
                with self.subTest(architecture=architecture):
                    config = make_config(pathlib.Path(temporary), architecture)
                    appliance.validate_aws_metadata(config, MetadataAWS(config))

    def test_metadata_failure_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(pathlib.Path(temporary))
            cases = {
                "architecture": {"Architecture": "arm64"},
                "state": {"State": "pending"},
                "root": {"RootDeviceType": "instance-store"},
                "virtualization": {"VirtualizationType": "paravirtual"},
                "image family": {"Name": "ubuntu-fixture"},
            }
            for name, overrides in cases.items():
                with self.subTest(name=name):
                    aws = MetadataAWS(config)
                    aws.image_overrides = overrides
                    with self.assertRaises(appliance.LifecycleError):
                        appliance.validate_aws_metadata(config, aws)
            aws = MetadataAWS(config)
            aws.type_architectures = ["arm64"]
            with self.assertRaisesRegex(appliance.LifecycleError, "does not support"):
                appliance.validate_aws_metadata(config, aws)


class SSMAndCleanupTest(unittest.TestCase):
    def test_ssm_secret_uses_protected_cli_input_file_not_argv(self):
        class FakeAWS:
            def __init__(self):
                self.payload = None
                self.command = None

            def json(inner, args, *, region=None):
                if args[1] == "put-parameter":
                    inner.command = list(args)
                    path = pathlib.Path(args[3].removeprefix("file://"))
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    inner.payload = json.loads(path.read_text())
                    return {"Version": 1}
                return {"Parameters": [{"ARN": f"arn:aws:ssm:{region}:123456789012:parameter/envelope-fixture/tailscale-auth"}]}

        with tempfile.TemporaryDirectory() as temporary:
            aws = FakeAWS()
            parameter = appliance.put_ssm_parameter(
                aws,
                run_dir=pathlib.Path(temporary),
                run_id="envelope-fixture",
                expires_at="2026-08-20T00:00:00Z",
                site="west",
                region="us-west-2",
                kms_key_arn="arn:aws:kms:us-west-2:123456789012:key/west",
                secret="fixture-auth-material",
            )
        self.assertEqual(aws.payload["Type"], "SecureString")
        self.assertFalse(aws.payload["Overwrite"])
        self.assertNotIn("fixture-auth-material", " ".join(aws.command))
        self.assertEqual(parameter["site"], "west")

    def test_device_cleanup_is_name_and_tag_scoped(self):
        class FakeAPI:
            def __init__(self):
                self.deleted = []
                self.devices = [
                    {"id": "west", "hostname": "envelope-fixture-west", "tags": ["tag:envelope-ci"]},
                    {"id": "east", "hostname": "envelope-fixture-east.fixture", "tags": ["tag:envelope-ci"]},
                    {"id": "wrong-tag", "hostname": "envelope-fixture-west", "tags": ["tag:other"]},
                    {"id": "wrong-name", "hostname": "other-west", "tags": ["tag:envelope-ci"]},
                ]

            def list_devices(inner):
                return inner.devices

            def delete_device(inner, device_id):
                inner.deleted.append(device_id)
                inner.devices = [device for device in inner.devices if device["id"] != device_id]

        api = FakeAPI()
        manifest = {
            "tailnet": {
                "expected_hostnames": ["envelope-fixture-west", "envelope-fixture-east"],
                "tag": "tag:envelope-ci",
                "nodes_expected": True,
                "device_ids": {},
            }
        }
        selected = appliance.cleanup_tailnet_devices(api, manifest, dry_run=False)
        self.assertEqual(set(selected), {"west", "east"})
        self.assertEqual(set(api.deleted), {"west", "east"})

    def test_partial_recovery_accepts_unambiguous_zero_one_or_two_node_subsets(self):
        class API:
            def __init__(self, devices):
                self.devices = devices
                self.deleted = []

            def list_devices(self):
                return self.devices

            def delete_device(self, device_id):
                self.deleted.append(device_id)
                self.devices = [device for device in self.devices if device["id"] != device_id]

        manifest = {
            "tailnet": {
                "expected_hostnames": ["envelope-fixture-west", "envelope-fixture-east"],
                "tag": "tag:envelope-ci",
                "nodes_expected": True,
                "device_ids": {},
            }
        }
        candidates = [
            {"id": "west", "hostname": "envelope-fixture-west", "tags": ["tag:envelope-ci"]},
            {"id": "east", "hostname": "envelope-fixture-east", "tags": ["tag:envelope-ci"]},
        ]
        for count in (0, 1, 2):
            with self.subTest(count=count):
                api = API(copy.deepcopy(candidates[:count]))
                selected = appliance.cleanup_tailnet_devices(api, manifest, dry_run=False)
                self.assertEqual(selected, sorted(device["id"] for device in candidates[:count]))
                self.assertEqual(api.deleted, selected)

    def test_partial_recovery_rejects_duplicate_hostname_tag_identity(self):
        class API:
            def list_devices(self):
                return [
                    {"id": "west-1", "hostname": "envelope-fixture-west", "tags": ["tag:envelope-ci"]},
                    {"id": "west-2", "hostname": "envelope-fixture-west", "tags": ["tag:envelope-ci"]},
                ]

        manifest = {
            "tailnet": {
                "expected_hostnames": ["envelope-fixture-west", "envelope-fixture-east"],
                "tag": "tag:envelope-ci",
                "nodes_expected": True,
                "device_ids": {},
            }
        }
        with self.assertRaisesRegex(appliance.LifecycleError, "ambiguous duplicate"):
            appliance.cleanup_tailnet_devices(API(), manifest, dry_run=False)

    def test_readiness_records_exact_full_field_node_ids_durably(self):
        class API:
            def list_devices(self):
                return [
                    {"id": "node-west", "hostname": "envelope-fixture-west", "tags": ["tag:envelope-ci"]},
                    {"id": "node-east", "hostname": "envelope-fixture-east", "tags": ["tag:envelope-ci"]},
                ]

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            store = appliance.ManifestStore(config, BackendAWS(config), root / "run")
            store.write(manifest, upload=False)
            identifiers = appliance.record_ready_devices(API(), store, manifest)
            self.assertEqual(identifiers, {"west": "node-west", "east": "node-east"})
            persisted = json.loads(store.path.read_text())
            self.assertEqual(persisted["tailnet"]["device_ids"], identifiers)
            self.assertEqual(persisted["phase"], "ready")

    def test_backend_cleanup_deletes_only_exact_run_key_versions(self):
        class FakeAWS:
            def __init__(self):
                self.deleted = []
                self.present = True

            def json(inner, args, *, region=None):
                if args[1] == "list-object-versions":
                    if not inner.present:
                        return {"Versions": [], "DeleteMarkers": []}
                    return {
                        "Versions": [
                            {"Key": "runs/run/state", "VersionId": "v1"},
                            {"Key": "runs/run/state-other", "VersionId": "foreign"},
                        ],
                        "DeleteMarkers": [{"Key": "runs/run/state", "VersionId": "d1"}],
                    }
                inner.deleted.append((args[args.index("--key") + 1], args[args.index("--version-id") + 1]))
                if len(inner.deleted) == 2:
                    inner.present = False
                return {}

        aws = FakeAWS()
        versions = appliance.delete_exact_object_versions(
            aws, bucket="operator-backend", key="runs/run/state", region="us-west-2", dry_run=False
        )
        self.assertEqual(versions, ["v1", "d1"])
        self.assertEqual(aws.deleted, [("runs/run/state", "v1"), ("runs/run/state", "d1")])

    def test_prepare_creates_two_references_and_never_persists_key_material(self):
        class FakeAWS:
            def __init__(self):
                self.sites = []
                self.phases = []

            def json(inner, args, *, region=None):
                if args[1] == "put-object":
                    body = pathlib.Path(args[args.index("--body") + 1])
                    inner.phases.append(json.loads(body.read_text())["phase"])
                    return {"VersionId": "manifest"}
                if args[1] == "put-parameter":
                    payload = json.loads(pathlib.Path(args[3].removeprefix("file://")).read_text())
                    self.assertEqual(payload["Value"], "fixture-auth-material")
                    inner.sites.append(region)
                    return {"Version": 1}
                if args[1] == "describe-parameters":
                    return {"Parameters": [{"ARN": f"arn:aws:ssm:{region}:123456789012:parameter/envelope-fixture/tailscale-auth"}]}
                raise AssertionError(args)

        class FakeTailscale:
            def create_auth_key(self, tag, description, expiry):
                return "key-fixture-id", "fixture-auth-material"

            def revoke_auth_key(self, key_id):
                raise AssertionError("unexpected rollback")

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            artifact = artifact_identity(root)
            config = make_config(root)
            aws = FakeAWS()
            with mock.patch.object(appliance, "run_preflight", return_value=(artifact, "123456789012")):
                manifest = appliance.prepare(config, aws, FakeTailscale(), root / "run")
            self.assertEqual(aws.sites, ["us-west-2", "us-east-1"])
            self.assertEqual(len(manifest["ssm_parameters"]), 2)
            for phase in (
                "preflight_complete",
                "auth_key_create_started",
                "auth_key_created",
                "west_secret_create_started",
                "west_secret_created",
                "east_secret_create_started",
                "east_secret_created",
                "prepared",
            ):
                self.assertIn(phase, aws.phases)
            for path in (root / "run").iterdir():
                if path.is_file():
                    self.assertNotIn("fixture-auth-material", path.read_text())

    def test_runner_loss_recovery_dry_run_preserves_shared_backend(self):
        class RecoveryAWS:
            def __init__(self, remote):
                self.remote = remote
                self.calls = []

            def json(inner, args, *, region=None):
                inner.calls.append(args[1])
                if args[1] == "get-object":
                    pathlib.Path(args[-1]).write_bytes(inner.remote)
                    return {"VersionId": "manifest"}
                if args[1] == "get-resources":
                    return {"ResourceTagMappingList": []}
                if args[1] == "list-object-versions":
                    return {"Versions": [], "DeleteMarkers": []}
                raise AssertionError(args)

            def object_exists(self, bucket, key, region):
                return False

        class FakeTailscale:
            def list_devices(self):
                return []

        class UnusedRunner:
            def run(self, *args, **kwargs):
                raise AssertionError("dry-run recovery must not invoke Terraform")

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            artifact = artifact_identity(root)
            manifest = appliance.new_manifest(config, artifact, "123456789012")
            manifest["tailnet"]["auth_key_id"] = "key-fixture-id"
            remote = (json.dumps(manifest, separators=(",", ":")) + "\n").encode()
            run_dir = root / "recovered"
            run_dir.mkdir()
            (run_dir / "runtime.tfvars.json").write_text("{}\n")
            aws = RecoveryAWS(remote)
            result = appliance.cleanup(
                config,
                aws,
                FakeTailscale(),
                UnusedRunner(),
                run_dir,
                root / "terraform",
                recover=True,
                dry_run=True,
                skip_destroy=True,
            )
            self.assertTrue(result["dry_run"])
            self.assertEqual(aws.calls.count("get-object"), 1)
            self.assertEqual(aws.calls.count("get-resources"), 2)
            self.assertEqual(config.backend["bucket"], "operator-backend")

    def test_cleanup_continues_after_destroy_exception_and_preserves_backend(self):
        class CleanupAWS:
            def __init__(self, config):
                self.config = config
                self.terminated = False
                self.deleted_parameters = []
                self.backend_version_reads = 0

            def json(inner, args, *, region=None):
                operation = args[1]
                if operation == "put-object":
                    return {}
                if operation == "delete-parameter":
                    inner.deleted_parameters.append((region, args[-1]))
                    return {}
                if operation == "describe-parameters":
                    return {"Parameters": []}
                if operation == "describe-instances":
                    return {
                        "Reservations": [
                            {"Instances": [{"InstanceId": "i-residual", "State": {"Name": "running"}}]}
                        ]
                    }
                if operation == "terminate-instances":
                    inner.terminated = True
                    return {}
                if operation == "get-resources":
                    if region == inner.config.sites["west"]["region"] and not inner.terminated:
                        return {
                            "ResourceTagMappingList": [
                                {
                                    "ResourceARN": "arn:aws:ec2:us-west-2:123456789012:instance/i-residual",
                                    "Tags": [
                                        {"Key": "EnvelopeRun", "Value": inner.config.run_id},
                                        {"Key": "ExpiresAt", "Value": inner.config.expires_at},
                                    ],
                                }
                            ]
                        }
                    return {"ResourceTagMappingList": []}
                if operation == "list-object-versions":
                    inner.backend_version_reads += 1
                    return {"Versions": [], "DeleteMarkers": []}
                raise AssertionError(args)

            def object_exists(self, bucket, key, region):
                return True

        class API:
            def __init__(self):
                self.devices = [
                    {"id": "west-node", "hostname": "envelope-fixture-west", "tags": ["tag:envelope-ci"]}
                ]
                self.deleted = []
                self.revoked = []

            def list_devices(self):
                return self.devices

            def delete_device(self, device_id):
                self.deleted.append(device_id)
                self.devices = [device for device in self.devices if device["id"] != device_id]

            def revoke_auth_key(self, key_id):
                self.revoked.append(key_id)

            def list_auth_keys(self):
                return []

        class UnusedRunner:
            pass

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            aws = CleanupAWS(config)
            api = API()
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            manifest["tailnet"]["auth_key_id"] = "run-key"
            manifest["tailnet"]["nodes_expected"] = True
            manifest["phase"] = "apply_started"
            store = appliance.ManifestStore(config, aws, root / "run")
            store.write(manifest)
            with mock.patch.object(
                appliance, "terraform_destroy", side_effect=appliance.LifecycleError("injected destroy failure")
            ):
                with self.assertRaisesRegex(appliance.LifecycleError, "Terraform destroy.*injected destroy failure"):
                    appliance.cleanup(
                        config,
                        aws,
                        api,
                        UnusedRunner(),
                        store.run_dir,
                        root / "terraform",
                        recover=False,
                        dry_run=False,
                        skip_destroy=False,
                    )
            self.assertEqual(api.deleted, ["west-node"])
            self.assertEqual(api.revoked, ["run-key"])
            self.assertEqual(len(aws.deleted_parameters), 2)
            self.assertTrue(aws.terminated)
            self.assertEqual(aws.backend_version_reads, 0)
            self.assertTrue(store.path.exists())
            self.assertEqual(store.load_local()["phase"], "cleanup_incomplete")

    def test_runner_loss_manifest_recovers_every_prepare_boundary_and_post_apply(self):
        class RecoveryAWS:
            def __init__(self, payload):
                self.payload = payload

            def json(self, args, *, region=None):
                if args[1] == "get-object":
                    pathlib.Path(args[-1]).write_bytes(self.payload)
                    return {}
                if args[1] == "get-resources":
                    return {"ResourceTagMappingList": []}
                if args[1] == "list-object-versions":
                    return {"Versions": [], "DeleteMarkers": []}
                raise AssertionError(args)

            def object_exists(self, bucket, key, region):
                return False

        class API:
            def __init__(self, nodes_expected):
                self.nodes_expected = nodes_expected

            def list_devices(self):
                if not self.nodes_expected:
                    return []
                return [
                    {"id": "west", "hostname": "envelope-fixture-west", "tags": ["tag:envelope-ci"]},
                    {"id": "east", "hostname": "envelope-fixture-east", "tags": ["tag:envelope-ci"]},
                ]

        class UnusedRunner:
            def run(self, *args, **kwargs):
                raise AssertionError("state-free recovery must not invoke Terraform")

        phases = (
            "preflight_complete",
            "auth_key_create_started",
            "auth_key_created",
            "west_secret_create_started",
            "west_secret_created",
            "east_secret_create_started",
            "east_secret_created",
            "prepared",
            "apply_started",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            for phase in phases:
                with self.subTest(phase=phase):
                    manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
                    manifest["phase"] = phase
                    if phase != "preflight_complete":
                        manifest["tailnet"]["auth_key_id"] = "key-fixture-id"
                    if phase == "apply_started":
                        manifest["tailnet"]["nodes_expected"] = True
                    payload = (json.dumps(manifest, separators=(",", ":")) + "\n").encode()
                    run_dir = root / f"recover-{phase}"
                    result = appliance.cleanup(
                        config,
                        RecoveryAWS(payload),
                        API(phase == "apply_started"),
                        UnusedRunner(),
                        run_dir,
                        root / "terraform",
                        recover=True,
                        dry_run=True,
                        skip_destroy=True,
                    )
                    self.assertTrue(result["dry_run"])

    def test_key_rotation_rolls_back_regional_partial_failure_before_revoking_old_key(self):
        class RotationAWS:
            def __init__(self, fail_east):
                self.values = {"us-west-2": "old-west", "us-east-1": "old-east"}
                self.fail_east = fail_east
                self.failed = False

            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "put-object":
                    return {}
                if operation == "get-parameter":
                    return {"Parameter": {"Value": self.values[region]}}
                if operation == "put-parameter":
                    payload = json.loads(pathlib.Path(args[3].removeprefix("file://")).read_text())
                    if self.fail_east and region == "us-east-1" and payload["Value"] == "new-material" and not self.failed:
                        self.failed = True
                        raise appliance.LifecycleError("injected east update failure")
                    self.values[region] = payload["Value"]
                    return {"Version": 2}
                if operation == "describe-parameters":
                    return {
                        "Parameters": [
                            {"ARN": f"arn:aws:ssm:{region}:123456789012:parameter/envelope-fixture/tailscale-auth"}
                        ]
                    }
                raise AssertionError(args)

        class RotationAPI:
            def __init__(self):
                self.revoked = []

            def create_auth_key(self, tag, description, expiry):
                return "new-key-id", "new-material"

            def revoke_auth_key(self, key_id):
                self.revoked.append(key_id)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            manifest["tailnet"]["auth_key_id"] = "old-key-id"
            manifest["phase"] = "prepared"

            failing_aws = RotationAWS(True)
            failing_api = RotationAPI()
            failing_store = appliance.ManifestStore(config, failing_aws, root / "failed")
            failing_store.write(copy.deepcopy(manifest))
            with self.assertRaisesRegex(appliance.LifecycleError, "injected"):
                appliance.rotate_auth_key(config, failing_aws, failing_api, failing_store.run_dir)
            self.assertEqual(failing_aws.values, {"us-west-2": "old-west", "us-east-1": "old-east"})
            self.assertEqual(failing_api.revoked, ["new-key-id"])
            self.assertEqual(failing_store.load_local()["tailnet"]["auth_key_id"], "old-key-id")

            success_aws = RotationAWS(False)
            success_api = RotationAPI()
            success_store = appliance.ManifestStore(config, success_aws, root / "success")
            success_store.write(copy.deepcopy(manifest))
            rotated = appliance.rotate_auth_key(config, success_aws, success_api, success_store.run_dir)
            self.assertEqual(success_aws.values, {"us-west-2": "new-material", "us-east-1": "new-material"})
            self.assertEqual(success_api.revoked, ["old-key-id"])
            self.assertEqual(rotated["tailnet"]["auth_key_id"], "new-key-id")
            self.assertEqual(rotated["tailnet"]["pending_revoke_key_ids"], [])
            self.assertNotIn("rotation", rotated["tailnet"])

    def test_key_rotation_rolls_back_write_when_post_write_verification_fails(self):
        class VerificationFailureAWS:
            def __init__(self, failing_region):
                self.values = {"us-west-2": "old-west", "us-east-1": "old-east"}
                self.failing_region = failing_region
                self.verification_failed = False

            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "put-object":
                    return {}
                if operation == "get-parameter":
                    return {"Parameter": {"Value": self.values[region]}}
                if operation == "put-parameter":
                    payload = json.loads(pathlib.Path(args[3].removeprefix("file://")).read_text())
                    self.values[region] = payload["Value"]
                    return {"Version": 2}
                if operation == "describe-parameters":
                    if (
                        region == self.failing_region
                        and self.values[region] == "new-material"
                        and not self.verification_failed
                    ):
                        self.verification_failed = True
                        raise appliance.LifecycleError("injected post-write describe failure")
                    return {
                        "Parameters": [
                            {"ARN": f"arn:aws:ssm:{region}:123456789012:parameter/envelope-fixture/tailscale-auth"}
                        ]
                    }
                raise AssertionError(args)

        class API:
            def __init__(self):
                self.revoked = []

            def create_auth_key(self, tag, description, expiry):
                return "new-key-id", "new-material"

            def revoke_auth_key(self, key_id):
                self.revoked.append(key_id)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            manifest["tailnet"]["auth_key_id"] = "old-key-id"
            manifest["phase"] = "prepared"
            for region in ("us-west-2", "us-east-1"):
                with self.subTest(region=region):
                    aws = VerificationFailureAWS(region)
                    api = API()
                    store = appliance.ManifestStore(config, aws, root / f"failure-{region}")
                    store.write(copy.deepcopy(manifest))
                    with self.assertRaisesRegex(appliance.LifecycleError, "post-write describe"):
                        appliance.rotate_auth_key(config, aws, api, store.run_dir)
                    self.assertEqual(aws.values, {"us-west-2": "old-west", "us-east-1": "old-east"})
                    self.assertEqual(api.revoked, ["new-key-id"])
                    persisted = store.load_local()
                    self.assertEqual(persisted["tailnet"]["auth_key_id"], "old-key-id")
                    self.assertNotIn("rotation", persisted["tailnet"])

    def test_cleanup_discovers_key_created_after_durable_rotation_intent(self):
        class API:
            def list_auth_keys(self):
                return [{"id": "unrecorded-new-key", "description": "Envelope acceptance envelope-fixture rotation-1"}]

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = make_config(root)
            manifest = appliance.new_manifest(config, artifact_identity(root), "123456789012")
            manifest["tailnet"]["auth_key_id"] = "old-key"
            manifest["tailnet"]["rotation"] = {
                "description": "Envelope acceptance envelope-fixture rotation-1",
                "new_key_id": None,
                "updated_sites": [],
            }
            manifest["phase"] = "key_rotation_create_started"
            self.assertEqual(appliance.recover_auth_key_ids(API(), manifest), ["old-key", "unrecorded-new-key"])


def render_template(path: pathlib.Path, values: dict[str, str]) -> str:
    text = path.read_text()
    pattern = re.compile(r"(?<!\$)\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

    def replace(match):
        name = match.group(1)
        if name not in values:
            raise AssertionError(f"missing template value {name}")
        return values[name]

    return pattern.sub(replace, text).replace("$${", "${")


class CloudInitSandboxTest(unittest.TestCase):
    def template_values(self, digest: str) -> dict[str, str]:
        return {
            "site": "west",
            "run_name": "envelope-fixture",
            "artifact_region": "us-west-2",
            "artifact_bucket": "fixture-artifact",
            "artifact_key": "artifacts/revision/envelope-linux-amd64",
            "artifact_sha256": digest,
            "artifact_revision": "a" * 40,
            "artifact_version": "fixture.1",
            "artifact_architecture": "amd64",
            "tailscale_version": "1.80.3",
            "tun_name": "envelope0",
            "tailscale_iface": "tailscale0",
            "underlay_iface": "ens5",
            "routing_mode": "manage",
            "gwlb_return_cidrs": "10.10.1.0/24",
            "local_delivery_cidrs": "10.10.2.0/24",
            "remote_tailnet_cidrs": "10.20.1.0/24,10.20.2.0/24",
            "routing_table_id": "100",
            "routing_rule_priority": "100",
        }

    def test_rendered_scripts_and_embedded_assets_have_valid_shell_syntax(self):
        digest = "a" * 64
        templates = [
            ROOT / "example/terraform/cloud-init/install-artifact.sh.tftpl",
            ROOT / "example/terraform/cloud-init/bootstrap.sh.tftpl",
        ]
        for template in templates:
            with self.subTest(template=template.name):
                rendered = render_template(template, self.template_values(digest))
                self.assertIsNone(appliance.SECRET_PATTERNS[0].search(rendered))
                self.assertNotIn("tailscale_auth_key", rendered)
                subprocess.run(["bash", "-n"], input=rendered, text=True, check=True, capture_output=True)
                for body in re.findall(r"<<'([A-Z_]+)'\n(.*?)\n\1", rendered, flags=re.DOTALL):
                    if body[1].startswith("#!/usr/bin/env bash"):
                        subprocess.run(["bash", "-n"], input=body[1], text=True, check=True, capture_output=True)
        bootstrap = render_template(templates[1], self.template_values(digest))
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW", bootstrap)
        self.assertIn("After=cloud-final.service network-online.target tailscaled.service", bootstrap)
        self.assertIn('"$binary" -t mangle -A FORWARD -j ENVELOPE-MSS', bootstrap)
        self.assertIn("snat", appliance.redact("snat"))

    def test_service_preflight_is_read_only_and_root_oneshot_owns_every_host_mutation(self):
        rendered = render_template(
            ROOT / "example/terraform/cloud-init/bootstrap.sh.tftpl", self.template_values("a" * 64)
        )
        host = re.search(
            r"cat >/usr/local/sbin/envelope-host-network <<'HOST_NETWORK'\n(.*?)\nHOST_NETWORK",
            rendered,
            flags=re.DOTALL,
        ).group(1)
        preflight = re.search(
            r"cat >/usr/local/sbin/envelope-preflight <<'PREFLIGHT'\n(.*?)\nPREFLIGHT",
            rendered,
            flags=re.DOTALL,
        ).group(1)
        host_unit = re.search(
            r"cat >/etc/systemd/system/envelope-host-network.service <<'HOST_UNIT'\n(.*?)\nHOST_UNIT",
            rendered,
            flags=re.DOTALL,
        ).group(1)
        service_unit = re.search(
            r"cat >/etc/systemd/system/envelope.service <<'ENVELOPE_UNIT'\n(.*?)\nENVELOPE_UNIT",
            rendered,
            flags=re.DOTALL,
        ).group(1)
        for mutation in (
            "/usr/sbin/sysctl -q -w \"$setting\"",
            "sysctl -q -w",
            "nft flush ruleset",
            '"$binary" -A',
        ):
            self.assertIn(mutation, host)
        self.assertNotIn("sysctl --system", host)
        self.assertNotIn("sysctl --system", preflight)
        self.assertNotIn(" -w ", preflight)
        self.assertNotIn("nft flush", preflight)
        self.assertNotIn("/usr/local/sbin/envelope-host-network", preflight)
        self.assertIn("User=root", host_unit)
        self.assertIn("Before=envelope.service", host_unit)
        self.assertIn("Environment=XTABLES_LOCKFILE=/run/envelope-host-network/xtables.lock", host_unit)
        self.assertIn("RuntimeDirectory=envelope-host-network", host_unit)
        self.assertIn("RuntimeDirectoryMode=0700", host_unit)
        self.assertEqual(
            re.findall(r"^ReadWritePaths=.*$", host_unit, re.MULTILINE),
            ["ReadWritePaths=/run/envelope-host-network"],
        )
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW", host_unit)
        self.assertIn("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW", host_unit)
        self.assertIn("User=envelope", service_unit)
        self.assertIn("Group=envelope", service_unit)
        self.assertNotRegex(service_unit, r"(?m)^User=root$")
        self.assertIn("ExecStartPre=!/usr/local/sbin/envelope-preflight", service_unit)
        self.assertIn("ExecStart=/usr/local/bin/envelope", service_unit)
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW", service_unit)
        self.assertIn("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW", service_unit)
        self.assertIn("ProtectKernelTunables=yes", service_unit)
        self.assertIn("net.ipv4.conf.default.rp_filter = 0", rendered)
        self.assertIn("net.ipv4.conf.*.rp_filter = 0", rendered)
        self.assertIn('"net.ipv4.conf.$envelope.rp_filter=0"', host)
        self.assertIn('"net.ipv4.conf.$iface.rp_filter=0"', host)
        self.assertIn('"$save_bin" -t "$table"', preflight)
        self.assertNotIn('rules=$("$save_bin")', preflight)

    def test_vendored_tailscale_module_has_only_exact_package_installation_before_auth(self):
        module = ROOT / "example/terraform/modules/tailscale-cloudinit"
        texts = [path.read_text() for path in module.rglob("*") if path.is_file()]
        combined = "\n".join(texts)
        self.assertNotIn("tailscale.com/install.sh", combined)
        self.assertNotIn("TRACK=", combined)
        self.assertIn("additional_parts", combined)
        self.assertIn("rpm --checksig", combined)
        self.assertIn("key ID 957f5868: OK", combined)
        self.assertIn("-----BEGIN PGP PUBLIC KEY BLOCK-----", combined)
        main = (module / "main.tf").read_text()
        self.assertLess(main.index("10-install-pinned-tailscale.sh"), main.index("20-setup-tailscale.sh"))
        user_data = (ROOT / "example/terraform/user_data.tf").read_text()
        self.assertNotIn('source  = "tailscale/tailscale/cloudinit"', user_data)
        self.assertIn("tailscale_1.80.3_x86_64.rpm", user_data)
        self.assertIn("aab2beef68039b77b143f07e1f7595433c2c6d7bc52aec871dcb8cec97f6aad2", user_data)
        self.assertIn("84ea51f9200a2c93362208f9617948fc8dbae06f3ed7faddf08eebc8a5371c32", user_data)
        self.assertIn(
            "53c6f7dfbd774839d9f37e6c5022ba952108aba9a0e556a56f292a9eb605d7cf  files/repo.gpg",
            (module / "SOURCE.sha256").read_text(),
        )
        for line in (module / "SOURCE.sha256").read_text().splitlines():
            digest, relative = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((module / relative).read_bytes()).hexdigest(), digest)
        rendered_install = render_template(
            module / "templates/install_tailscale.sh.tftpl",
            {
                "package_version": "1.80.3",
                "package_url": "https://fixture.invalid/tailscale_1.80.3_x86_64.rpm",
                "package_sha256": "a" * 64,
                "signing_key": "Zml4dHVyZQ==",
                "max_retries": "3",
                "retry_delay": "1",
            },
        )
        rendered_setup = render_template(
            module / "templates/setup_tailscale.sh.tftpl",
            {
                "auth_key": "command:/fixture/resolver",
                "package_version": "1.80.3",
                "max_retries": "3",
                "retry_delay": "1",
                "hostname": "fixture-west",
                "advertise_tags": "tag:fixture",
                "advertise_routes": "10.0.0.0/24",
                "accept_routes": "true",
                "snat_subnet_routes": "false",
                "netfilter_mode": "off",
                "timeout": "2m",
            },
        )
        for rendered in (rendered_install, rendered_setup):
            subprocess.run(["bash", "-n"], input=rendered, text=True, check=True, capture_output=True)

    def test_checksum_verified_atomic_install_and_mismatch_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "source"
            source.write_bytes(b"fixture-static-linux-artifact")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            fake_aws = root / "aws"
            fake_systemctl = root / "systemctl"
            service_log = root / "service.log"
            fake_aws.write_text("#!/usr/bin/env bash\nset -euo pipefail\ncp \"$FAKE_ARTIFACT\" \"${@: -1}\"\n")
            fake_systemctl.write_text("#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >>\"$SERVICE_LOG\"\n")
            fake_aws.chmod(0o755)
            fake_systemctl.chmod(0o755)
            installer = render_template(
                ROOT / "example/terraform/cloud-init/install-artifact.sh.tftpl", self.template_values(digest)
            )
            env = {
                **os.environ,
                "ENVELOPE_INSTALL_ROOT": str(root / "target"),
                "AWS_BIN": str(fake_aws),
                "SYSTEMCTL_BIN": str(fake_systemctl),
                "FAKE_ARTIFACT": str(source),
                "SERVICE_LOG": str(service_log),
                "SHA256_BIN": "/usr/bin/shasum" if pathlib.Path("/usr/bin/shasum").exists() else "/usr/bin/sha256sum",
                "INSTALL_BIN": "/usr/bin/install",
                "MV_BIN": "/bin/mv",
            }
            if env["SHA256_BIN"].endswith("shasum"):
                wrapper = root / "sha256"
                wrapper.write_text("#!/usr/bin/env bash\nexec /usr/bin/shasum -a 256 \"$@\"\n")
                wrapper.chmod(0o755)
                env["SHA256_BIN"] = str(wrapper)
            subprocess.run(["bash"], input=installer, text=True, env=env, check=True, capture_output=True)
            target = root / "target/usr/local/bin/envelope"
            self.assertEqual(target.read_bytes(), source.read_bytes())
            self.assertTrue(target.stat().st_mode & stat.S_IXUSR)
            self.assertIn(digest, (root / "target/etc/envelope/artifact.env").read_text())

            target.write_bytes(b"known-good-old-artifact")
            bad_installer = render_template(
                ROOT / "example/terraform/cloud-init/install-artifact.sh.tftpl", self.template_values("0" * 64)
            )
            result = subprocess.run(["bash"], input=bad_installer, text=True, env=env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(target.read_bytes(), b"known-good-old-artifact")
            self.assertIn("disable --now envelope.service", service_log.read_text())

    def test_service_preflight_rejects_backend_and_route_withdrawal(self):
        rendered = render_template(
            ROOT / "example/terraform/cloud-init/bootstrap.sh.tftpl", self.template_values("a" * 64)
        )
        match = re.search(
            r"cat >/usr/local/sbin/envelope-preflight <<'PREFLIGHT'\n(.*?)\nPREFLIGHT",
            rendered,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        preflight = match.group(1)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)

            def executable(name: str, body: str) -> str:
                path = root / name
                path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body)
                path.chmod(0o755)
                return str(path)

            tailscale = executable(
                "tailscale",
                """
if [[ ${1:-} == version ]]; then printf '%s\n' '1.80.3'; exit 0; fi
printf '{"Version":"1.80.3","TUN":true,"BackendState":"%s","Health":[],"Self":{"AllowedIPs":["10.10.1.0/24","10.10.2.0/24"]},"Peer":{"fixture":{"PrimaryRoutes":["10.20.1.0/24","10.20.2.0/24"]}}}\n' "$BACKEND_STATE"
""",
            )
            ip = executable(
                "ip",
                """
if [[ $ROUTES_READY == true ]]; then
  cidr=${@: -1}
  printf '[{"dst":"%s","dev":"tailscale0","type":"unicast"}]\n' "$cidr"
else
  printf '%s\n' '[]'
fi
""",
            )
            timeout = executable("timeout", "shift\nexec \"$@\"\n")
            success = executable("success", "exit 0\n")
            sha = executable("sha256", "cat >/dev/null\nexit 0\n")
            sysctl = executable(
                "sysctl",
                """
case "${@: -1}" in
  net.ipv4.ip_forward|net.ipv6.conf.all.forwarding) printf '%s\n' 1 ;;
  net.ipv4.conf.envelope0.rp_filter) printf '%s\n' 0 ;;
  net.ipv4.conf.*.rp_filter) printf '%s\n' 0 ;;
  *) exit 1 ;;
esac
""",
            )
            filter_rules = """*filter
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-N ENVELOPE-FORWARD
-A FORWARD -j ENVELOPE-FORWARD
-A ENVELOPE-FORWARD -i ens5 -o tailscale0 -j ACCEPT
-A ENVELOPE-FORWARD -i tailscale0 -o ens5 -j ACCEPT
-A ENVELOPE-FORWARD -i envelope0 -o tailscale0 -j ACCEPT
-A ENVELOPE-FORWARD -i tailscale0 -o envelope0 -j ACCEPT
COMMIT
"""
            mangle_rules = """*mangle
-N ENVELOPE-MSS
-A FORWARD -j ENVELOPE-MSS
-A ENVELOPE-MSS -i ens5 -o tailscale0 -p tcp -j TCPMSS
-A ENVELOPE-MSS -i tailscale0 -o ens5 -p tcp -j TCPMSS
-A ENVELOPE-MSS -i envelope0 -o tailscale0 -p tcp -j TCPMSS
-A ENVELOPE-MSS -i tailscale0 -o envelope0 -p tcp -j TCPMSS
COMMIT
"""
            save_body = """
printf '%s %s\n' "${0##*/}" "$*" >>"$SAVE_LOG"
table=${@: -1}
binary=${0##*/}
if [[ -n ${DENIED_TABLE:-} && "$table" == "$DENIED_TABLE" ]]; then
  printf 'Permission denied while opening xtables lock\nsecond line %0400d\n' 0 >&2
  exit 1
fi
if [[ -n ${EXTRA_ERROR_TABLE:-} && "$table" == "$EXTRA_ERROR_TABLE" ]]; then
  printf '%s v1.8.9 (legacy): Cannot initialize: Table does not exist (do you need to insmod?)\nunexpected extra stderr\n' "$binary" >&2
  exit 1
fi
if [[ "$table" == security || ( -n ${MISSING_TABLE:-} && "$table" == "$MISSING_TABLE" ) ]]; then
  printf '%s v1.8.9 (legacy): Cannot initialize: Table does not exist (do you need to insmod?)\n' "$binary" >&2
  exit 1
fi
cat "$RULES_DIR/$table"
"""
            save = executable("iptables-save", save_body)
            save6 = executable("ip6tables-save", save_body)
            nft = executable("nft", "printf '%s\n' '{\"nftables\":[{\"metainfo\":{}}]}'\n")
            rules_dir = root / "rules"
            rules_dir.mkdir()
            (rules_dir / "filter").write_text(filter_rules)
            (rules_dir / "mangle").write_text(mangle_rules)
            for table in ("raw", "nat", "security"):
                (rules_dir / table).write_text(f"*{table}\nCOMMIT\n")
            env = {
                **os.environ,
                "TAILSCALE_BIN": tailscale,
                "TIMEOUT_BIN": timeout,
                "JQ_BIN": shutil.which("jq") or "/usr/bin/jq",
                "IP_BIN": ip,
                "SYSTEMCTL_BIN": success,
                "SYSCTL_BIN": sysctl,
                "IPTABLES_SAVE_BIN": save,
                "IP6TABLES_SAVE_BIN": save6,
                "NFT_BIN": nft,
                "SHA256_BIN": sha,
                "ENVELOPE_BIN": str(root / "envelope"),
                "SLEEP_BIN": success,
                "PREFLIGHT_MAX_ATTEMPTS": "1",
                "PREFLIGHT_RETRY_SECONDS": "0",
                "BACKEND_STATE": "Running",
                "ROUTES_READY": "true",
                "RULES_DIR": str(rules_dir),
                "SAVE_LOG": str(root / "save.log"),
                "MISSING_TABLE": "",
                "DENIED_TABLE": "",
                "EXTRA_ERROR_TABLE": "",
            }
            save_log = pathlib.Path(env["SAVE_LOG"])
            save_log.write_text("")
            healthy = subprocess.run(["bash"], input=preflight, text=True, env=env, capture_output=True)
            self.assertEqual(healthy.returncode, 0, healthy.stderr)
            expected_tables = [
                f"{binary} -t {table}"
                for binary in ("iptables-save", "ip6tables-save")
                for table in ("raw", "mangle", "nat", "filter", "security")
            ]
            self.assertEqual(save_log.read_text().splitlines(), expected_tables)

            for name, overrides, table, detail in (
                ("absent filter", {"MISSING_TABLE": "filter"}, "filter", "Table does not exist"),
                ("absent mangle", {"MISSING_TABLE": "mangle"}, "mangle", "Table does not exist"),
                ("optional table permission error", {"DENIED_TABLE": "raw"}, "raw", "Permission denied"),
                ("optional table extra stderr", {"EXTRA_ERROR_TABLE": "nat"}, "nat", "unexpected extra stderr"),
            ):
                with self.subTest(name=name):
                    save_log.write_text("")
                    failed = subprocess.run(
                        ["bash"], input=preflight, text=True, env={**env, **overrides}, capture_output=True
                    )
                    self.assertNotEqual(failed.returncode, 0)
                    self.assertEqual(
                        save_log.read_text().splitlines(),
                        [
                            f"iptables-save -t {candidate}"
                            for candidate in ("raw", "mangle", "nat", "filter", "security")
                        ],
                    )
                    diagnostic = next(
                        line for line in failed.stderr.splitlines() if line.startswith("legacy firewall inspection failed:")
                    )
                    self.assertIn(f"binary=iptables-save table={table} status=1", diagnostic)
                    self.assertIn(detail, diagnostic)
                    self.assertLessEqual(len(diagnostic), 400)
                    if name == "optional table permission error":
                        self.assertIn("lock second line", diagnostic)

            for name, overrides in {
                "backend": {"BACKEND_STATE": "Stopped"},
                "route withdrawal": {"ROUTES_READY": "false"},
            }.items():
                with self.subTest(name=name):
                    failed = subprocess.run(
                        ["bash"], input=preflight, text=True, env={**env, **overrides}, capture_output=True
                    )
                    self.assertNotEqual(failed.returncode, 0)
                    self.assertIn("timed out", failed.stderr)


class ReadinessTest(unittest.TestCase):
    def test_ssm_and_target_waits_require_success_and_single_healthy_target(self):
        class FakeAWS:
            def json(self, args, *, region=None):
                operation = args[1]
                if operation == "describe-instance-information":
                    return {"InstanceInformationList": [{"PingStatus": "Online"}]}
                if operation == "send-command":
                    return {"Command": {"CommandId": "command-fixture"}}
                if operation == "get-command-invocation":
                    return {"Status": "Success"}
                if operation == "describe-target-health":
                    return {"TargetHealthDescriptions": [{"TargetHealth": {"State": "healthy"}}]}
                raise AssertionError(args)

        aws = FakeAWS()
        deadline = time.monotonic() + 1
        appliance.wait_for_instance(aws, region="us-west-2", instance_id="i-fixture", deadline=deadline, sleep=lambda _: None)
        appliance.wait_for_target(
            aws, region="us-west-2", target_group_arn="arn:fixture", deadline=deadline, sleep=lambda _: None
        )
        commands = "\n".join(appliance.READINESS_COMMANDS)
        self.assertIn("cloud-init status --wait", commands)
        self.assertIn("envelope-preflight", commands)
        self.assertNotIn("get-parameter", commands)

    def test_diagnostics_are_bounded_and_redacted(self):
        class FakeAWS:
            def json(self, args, *, region=None):
                if args[1] == "send-command":
                    return {"Command": {"CommandId": "diagnostic-fixture"}}
                return {
                    "Status": "Success",
                    "StandardOutputContent": "auth_key=fixture-sensitive-value",
                    "StandardErrorContent": "",
                }

        result = appliance.collect_diagnostics(
            FakeAWS(), {"region": "us-west-2"}, "i-fixture", sleep=lambda _: None
        )
        self.assertEqual(result["status"], "Success")
        self.assertNotIn("fixture-sensitive-value", result["stdout"])
        self.assertIn("[REDACTED]", result["stdout"])


if __name__ == "__main__":
    unittest.main()
