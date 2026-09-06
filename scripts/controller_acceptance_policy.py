"""Closed IAM boundaries for observation and narrowly scoped quiescence."""
from __future__ import annotations

from typing import Any

import controller_acceptance_contract as contract


def boundary_policy(h: dict[str, Any], phase: str) -> dict[str, Any]:
    contract.require(phase in {"observe", "quiesce"}, "unsupported narrow role")
    account = contract.ROLE.fullmatch(h["revocation"]["role_arn"]).group(1)  # type: ignore[union-attr]
    actors = h["actors"]
    fault_arns = [f"arn:aws:ec2:{a['region']}:{account}:instance/{a['instance_id']}" for a in actors if a["actor_type"] in {"router", "controller"}]
    start_arns = fault_arns if phase == "observe" else [f"arn:aws:ec2:{a['region']}:{account}:instance/{a['instance_id']}" for a in actors if a["actor_type"] == "router"]
    stop_arns = fault_arns if phase == "observe" else [f"arn:aws:ec2:{a['region']}:{account}:instance/{a['instance_id']}" for a in actors if a["actor_type"] == "controller"]
    workload_arns = [f"arn:aws:ec2:{a['region']}:{account}:instance/{a['instance_id']}" for a in actors if a["actor_type"] == "workload"]
    document_arns = sorted({f"arn:aws:ssm:{a['region']}::document/AWS-RunShellScript" for a in actors if a["actor_type"] == "workload"})
    claim = h["claim"]
    handoff_key = f"runs/{h['run_id']}/handoff/{h['invocation_id']}/handoff.json"
    evidence = h["evidence_store"]
    quiescence_key = evidence["prefix"] + "quiescence.json"
    read_objects = [f"arn:aws:s3:::{claim['bucket']}/{claim['key']}", f"arn:aws:s3:::{claim['bucket']}/{handoff_key}"]
    if phase == "quiesce":
        read_objects.append(f"arn:aws:s3:::{evidence['bucket']}/{quiescence_key}")
    write_objects = [f"arn:aws:s3:::{evidence['bucket']}/{evidence['prefix']}{name}" for name in (["live.json", "fault-journal.json"] if phase == "observe" else ["quiescence.json"])]
    read_objects += write_objects
    table = h["topology"]["dynamodb"]
    table_arn = f"arn:aws:dynamodb:{table['region']}:{account}:table/{table['table']}"
    role_arns = [h["revocation"]["role_arn"], h["revocation"]["lifecycle_role_arn"], *(r["arn"] for r in h["roles"].values())]
    read_actions = ["ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeRouteTables", "ec2:DescribeSubnets", "dynamodb:GetItem", "s3:GetObjectVersion", "s3:ListBucketVersions", "s3:PutObject", "kms:Decrypt", "iam:GetRole", "iam:GetRolePolicy", "sts:GetCallerIdentity", "ec2:StartInstances", "ec2:StopInstances"]
    if phase == "observe":
        read_actions += ["ssm:SendCommand", "ssm:GetCommandInvocation", "ssm:CancelCommand"]
    statements: list[dict[str, Any]] = [
        {"Sid": "DenyEveryOtherAPI", "Effect": "Deny", "NotAction": read_actions, "Resource": "*"},
        {"Sid": "ReadCloud", "Effect": "Allow", "Action": read_actions[:4], "Resource": "*", "Condition": {"StringEquals": {"aws:RequestedRegion": sorted({a["region"] for a in actors})}}},
        {"Sid": "ExactStartActors", "Effect": "Allow", "Action": "ec2:StartInstances", "Resource": start_arns},
        {"Sid": "DenyOtherStarts", "Effect": "Deny", "Action": "ec2:StartInstances", "NotResource": start_arns},
        {"Sid": "ExactStopActors", "Effect": "Allow", "Action": "ec2:StopInstances", "Resource": stop_arns},
        {"Sid": "DenyOtherStops", "Effect": "Deny", "Action": "ec2:StopInstances", "NotResource": stop_arns},
        {"Sid": "ReadDurableAuthority", "Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": table_arn, "Condition": {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["deployment#" + h["run_id"], *(f"observations#{h['run_id']}#{h['topology_identity']['canonical_sha256']}#{cid}" for cid in h["controller"]["controller_ids"])]}, "Null": {"dynamodb:LeadingKeys": "false"}}},
        {"Sid": "DenyForeignTables", "Effect": "Deny", "Action": "dynamodb:GetItem", "NotResource": table_arn},
        {"Sid": "ReadOnlyPublicHandoff", "Effect": "Allow", "Action": "s3:GetObjectVersion", "Resource": read_objects},
        {"Sid": "DenyPrivateDeploymentState", "Effect": "Deny", "Action": "s3:GetObjectVersion", "NotResource": read_objects},
        {"Sid": "PublishOnlyOwnEvidence", "Effect": "Allow", "Action": "s3:PutObject", "Resource": write_objects},
        {"Sid": "DenyOtherPublications", "Effect": "Deny", "Action": "s3:PutObject", "NotResource": write_objects},
        {"Sid": "CheckExactClaimVersionSet", "Effect": "Allow", "Action": "s3:ListBucketVersions", "Resource": f"arn:aws:s3:::{claim['bucket']}", "Condition": {"StringEquals": {"s3:prefix": claim["key"]}}},
        {"Sid": "InspectPhaseTrust", "Effect": "Allow", "Action": ["iam:GetRole", "iam:GetRolePolicy"], "Resource": role_arns},
        {"Sid": "ReadOwnSession", "Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"},
        {"Sid": "DecryptPublicAuthorityObjects", "Effect": "Allow", "Action": "kms:Decrypt", "Resource": h["authority_kms_key_arn"], "Condition": {"StringEquals": {"kms:ViaService": f"s3.{claim['region']}.amazonaws.com", "kms:CallerAccount": account, "kms:EncryptionContext:aws:s3:arn": read_objects}}},
    ]
    if phase == "observe":
        statements += [
            {"Sid": "WorkloadProbesOnly", "Effect": "Allow", "Action": "ssm:SendCommand", "Resource": workload_arns + document_arns},
            {"Sid": "DenyOtherRemoteExecution", "Effect": "Deny", "Action": "ssm:SendCommand", "NotResource": workload_arns + document_arns},
            {"Sid": "ProbeReadback", "Effect": "Allow", "Action": ["ssm:GetCommandInvocation", "ssm:CancelCommand"], "Resource": "*"},
        ]
    return {"Version": "2012-10-17", "Statement": statements}
