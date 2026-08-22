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
import math
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


SCHEMA = 2
ARCHITECTURES = {"amd64": "x86_64", "arm64": "arm64"}
TAILSCALE_VERSION = "1.80.3"
SECRET_PATTERNS = (
    re.compile(r"tskey-[A-Za-z0-9_-]+", re.IGNORECASE),
    re.compile(r"(?i)(access[_-]?key|secret|token|auth[_-]?key)([\"'= :]+)([^\s,\"'}]+)"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
)
RUN_RE = re.compile(r"^[a-z][a-z0-9-]{2,17}[a-z0-9]$")
DEPLOYMENT_SITES = ("west", "east")
WORKLOAD_ROLES = ("initiator", "responder")
WORKLOAD_OUTPUT_FIELDS = (
    "instance_id",
    "private_ip",
    "az_key",
    "availability_zone",
    "subnet_id",
    "cidr",
    "route_table_id",
)
DEPLOYMENT_INSTANCE_ID_RE = re.compile(r"i-[A-Za-z0-9][A-Za-z0-9-]{0,127}")
DEPLOYMENT_SUBNET_ID_RE = re.compile(r"subnet-[A-Za-z0-9][A-Za-z0-9-]{0,127}")
DEPLOYMENT_ROUTE_TABLE_ID_RE = re.compile(r"rtb-[A-Za-z0-9][A-Za-z0-9-]{0,127}")
DEPLOYMENT_TARGET_GROUP_ARN_RE = re.compile(r"arn:[A-Za-z0-9:/._-]{1,2048}")
DEPLOYMENT_REGION_RE = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+")
DEPLOYMENT_AZ_RE = re.compile(r"([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)[a-z]")
E2E_LOAD_PROFILE_FIELDS = (
    "profile_id",
    "approved_at",
    "safe_inner_mtu",
    "maximum_tcp_mss",
    "sustained_tcp_duration_seconds",
    "minimum_sustained_tcp_bytes",
    "iperf_duration_seconds",
    "minimum_throughput_mbps",
    "concurrent_duration_seconds",
    "concurrent_tcp_flows",
    "concurrent_udp_flows",
    "maximum_udp_loss_percent",
    "maximum_p99_latency_ms",
)
E2E_LOAD_PROFILE_INTEGER_BOUNDS = {
    "safe_inner_mtu": (576, 1500),
    "maximum_tcp_mss": (536, 1460),
    "sustained_tcp_duration_seconds": (3, 120),
    "minimum_sustained_tcp_bytes": (1, 1_000_000_000),
    "iperf_duration_seconds": (3, 120),
    "concurrent_duration_seconds": (3, 120),
    "concurrent_tcp_flows": (1, 32),
    "concurrent_udp_flows": (1, 32),
}
E2E_LOAD_PROFILE_NUMBER_BOUNDS = {
    "minimum_throughput_mbps": (0.001, 100_000.0),
    "maximum_udp_loss_percent": (0.0, 100.0),
    "maximum_p99_latency_ms": (0.001, 60_000.0),
}
E2E_LOAD_PROFILE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
E2E_LOAD_PROFILE_APPROVED_AT_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
CANONICAL_UTC_TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
TAILSCALE_OAUTH_REFRESH_MARGIN_SECONDS = 30.0
TAILSCALE_OAUTH_MAX_EXPIRES_IN_SECONDS = 24 * 60 * 60
IAM_SIMULATION_ACTION_CHUNK_SIZE = 100

AWS_OPERATOR_ACTIONS = tuple(
    sorted(
        {
            "ec2:AllocateAddress",
            "ec2:AssociateRouteTable",
            "ec2:AttachInternetGateway",
            "ec2:AttachNetworkInterface",
            "ec2:AttachVolume",
            "ec2:AuthorizeSecurityGroupEgress",
            "ec2:AuthorizeSecurityGroupIngress",
            "ec2:CreateFlowLogs",
            "ec2:CreateInternetGateway",
            "ec2:CreateNatGateway",
            "ec2:CreateNetworkAcl",
            "ec2:CreateNetworkAclEntry",
            "ec2:CreateNetworkInterface",
            "ec2:CreateRoute",
            "ec2:CreateRouteTable",
            "ec2:CreateSecurityGroup",
            "ec2:CreateSubnet",
            "ec2:CreateTags",
            "ec2:CreateVolume",
            "ec2:CreateVpc",
            "ec2:CreateVpcEndpoint",
            "ec2:CreateVpcEndpointServiceConfiguration",
            "ec2:DeleteFlowLogs",
            "ec2:DeleteInternetGateway",
            "ec2:DeleteNatGateway",
            "ec2:DeleteNetworkAcl",
            "ec2:DeleteNetworkAclEntry",
            "ec2:DeleteNetworkInterface",
            "ec2:DeleteRoute",
            "ec2:DeleteRouteTable",
            "ec2:DeleteSecurityGroup",
            "ec2:DeleteSubnet",
            "ec2:DeleteTags",
            "ec2:DeleteVolume",
            "ec2:DeleteVpc",
            "ec2:DeleteVpcEndpointServiceConfigurations",
            "ec2:DeleteVpcEndpoints",
            "ec2:DescribeAccountAttributes",
            "ec2:DescribeAddresses",
            "ec2:DescribeAvailabilityZones",
            "ec2:DescribeFlowLogs",
            "ec2:DescribeImages",
            "ec2:DescribeIamInstanceProfileAssociations",
            "ec2:DescribeInstanceAttribute",
            "ec2:DescribeInstanceCreditSpecifications",
            "ec2:DescribeInstances",
            "ec2:DescribeInstanceStatus",
            "ec2:DescribeInstanceTypeOfferings",
            "ec2:DescribeInstanceTypes",
            "ec2:DescribeInternetGateways",
            "ec2:DescribeNatGateways",
            "ec2:DescribeNetworkAcls",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DescribeRegions",
            "ec2:DescribeRouteTables",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeSecurityGroupRules",
            "ec2:DescribeSubnets",
            "ec2:DescribeTags",
            "ec2:DescribeVolumes",
            "ec2:DescribeVolumeAttribute",
            "ec2:DescribeVolumesModifications",
            "ec2:DescribeVpcAttribute",
            "ec2:DescribeVpcEndpointServiceConfigurations",
            "ec2:DescribeVpcEndpointServicePermissions",
            "ec2:DescribeVpcEndpointServices",
            "ec2:DescribeVpcEndpoints",
            "ec2:DescribeVpcs",
            "ec2:DetachInternetGateway",
            "ec2:DetachNetworkInterface",
            "ec2:DetachVolume",
            "ec2:DisassociateAddress",
            "ec2:DisassociateRouteTable",
            "ec2:ModifyInstanceAttribute",
            "ec2:ModifyNetworkInterfaceAttribute",
            "ec2:ModifySubnetAttribute",
            "ec2:ModifyVpcAttribute",
            "ec2:ModifyVpcEndpoint",
            "ec2:ModifyVpcEndpointServiceConfiguration",
            "ec2:RebootInstances",
            "ec2:ReleaseAddress",
            "ec2:ReplaceNetworkAclAssociation",
            "ec2:ReplaceNetworkAclEntry",
            "ec2:ReplaceRoute",
            "ec2:ReplaceRouteTableAssociation",
            "ec2:RevokeSecurityGroupEgress",
            "ec2:RevokeSecurityGroupIngress",
            "ec2:RunInstances",
            "ec2:TerminateInstances",
            "elasticloadbalancing:AddTags",
            "elasticloadbalancing:CreateListener",
            "elasticloadbalancing:CreateLoadBalancer",
            "elasticloadbalancing:CreateTargetGroup",
            "elasticloadbalancing:DeleteListener",
            "elasticloadbalancing:DeleteLoadBalancer",
            "elasticloadbalancing:DeleteTargetGroup",
            "elasticloadbalancing:DeregisterTargets",
            "elasticloadbalancing:DescribeAccountLimits",
            "elasticloadbalancing:DescribeListenerAttributes",
            "elasticloadbalancing:DescribeListeners",
            "elasticloadbalancing:DescribeLoadBalancerAttributes",
            "elasticloadbalancing:DescribeLoadBalancers",
            "elasticloadbalancing:DescribeTags",
            "elasticloadbalancing:DescribeTargetGroupAttributes",
            "elasticloadbalancing:DescribeTargetGroups",
            "elasticloadbalancing:DescribeTargetHealth",
            "elasticloadbalancing:ModifyLoadBalancerAttributes",
            "elasticloadbalancing:ModifyListenerAttributes",
            "elasticloadbalancing:ModifyTargetGroup",
            "elasticloadbalancing:ModifyTargetGroupAttributes",
            "elasticloadbalancing:RegisterTargets",
            "elasticloadbalancing:SetSubnets",
            "iam:AddRoleToInstanceProfile",
            "iam:CreateInstanceProfile",
            "iam:CreateRole",
            "iam:DeleteInstanceProfile",
            "iam:DeleteRole",
            "iam:DeleteRolePolicy",
            "iam:DetachRolePolicy",
            "iam:GetAccountSummary",
            "iam:GetInstanceProfile",
            "iam:GetRole",
            "iam:GetRolePolicy",
            "iam:ListAttachedRolePolicies",
            "iam:ListInstanceProfilesForRole",
            "iam:ListInstanceProfileTags",
            "iam:ListRolePolicies",
            "iam:ListRoleTags",
            "iam:PassRole",
            "iam:PutRolePolicy",
            "iam:RemoveRoleFromInstanceProfile",
            "iam:SimulateCustomPolicy",
            "iam:SimulatePrincipalPolicy",
            "iam:TagInstanceProfile",
            "iam:TagRole",
            "iam:UntagInstanceProfile",
            "iam:UntagRole",
            "iam:UpdateAssumeRolePolicy",
            "kms:Decrypt",
            "kms:DescribeKey",
            "kms:Encrypt",
            "kms:GenerateDataKey",
            "kms:GetKeyPolicy",
            "logs:CreateLogGroup",
            "logs:DeleteLogGroup",
            "logs:DeleteRetentionPolicy",
            "logs:DescribeLogGroups",
            "logs:FilterLogEvents",
            "logs:ListTagsForResource",
            "logs:PutRetentionPolicy",
            "logs:TagResource",
            "logs:UntagResource",
            "s3:CreateBucket",
            "s3:DeleteBucket",
            "s3:DeleteBucketPolicy",
            "s3:DeleteObject",
            "s3:DeleteObjectVersion",
            "s3:GetAccelerateConfiguration",
            "s3:GetBucketAcl",
            "s3:GetBucketCORS",
            "s3:GetBucketLocation",
            "s3:GetBucketLogging",
            "s3:GetBucketNotification",
            "s3:GetBucketObjectLockConfiguration",
            "s3:GetBucketOwnershipControls",
            "s3:GetBucketPolicy",
            "s3:GetBucketPolicyStatus",
            "s3:GetBucketPublicAccessBlock",
            "s3:GetBucketRequestPayment",
            "s3:GetBucketTagging",
            "s3:GetBucketVersioning",
            "s3:GetBucketWebsite",
            "s3:GetEncryptionConfiguration",
            "s3:GetLifecycleConfiguration",
            "s3:GetObject",
            "s3:GetObjectAttributes",
            "s3:GetObjectTagging",
            "s3:GetReplicationConfiguration",
            "s3:ListAllMyBuckets",
            "s3:ListBucket",
            "s3:ListBucketVersions",
            "s3:PutBucketOwnershipControls",
            "s3:PutBucketPolicy",
            "s3:PutBucketPublicAccessBlock",
            "s3:PutBucketTagging",
            "s3:PutBucketVersioning",
            "s3:PutEncryptionConfiguration",
            "s3:PutObject",
            "s3:PutObjectTagging",
            "servicequotas:GetServiceQuota",
            "ssm:AddTagsToResource",
            "ssm:CancelCommand",
            "ssm:DeleteParameter",
            "ssm:DescribeInstanceInformation",
            "ssm:DescribeParameters",
            "ssm:GetCommandInvocation",
            "ssm:GetParameter",
            "ssm:ListTagsForResource",
            "ssm:PutParameter",
            "ssm:RemoveTagsFromResource",
            "ssm:SendCommand",
            "tag:GetResources",
        }
    )
)
AWS_RUN_INSTANCES_DRY_RUN_ACTION = "ec2:RunInstances"
AWS_IAM_SIMULATED_OPERATOR_ACTIONS = tuple(
    action for action in AWS_OPERATOR_ACTIONS if action != AWS_RUN_INSTANCES_DRY_RUN_ACTION
)
AWS_RUN_INSTANCES_DRY_RUN_SUCCESS = (
    "An error occurred (DryRunOperation) when calling the RunInstances operation: "
    "Request would have succeeded, but DryRun flag is set."
)


def action_resource_contract(
    groups: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...],
) -> dict[str, tuple[str, ...]]:
    contract: dict[str, tuple[str, ...]] = {}
    for resource_kinds, actions in groups:
        if not resource_kinds or not actions:
            raise RuntimeError("AWS action/resource contract contains an empty group")
        for action in actions:
            if action in contract:
                raise RuntimeError(f"AWS action/resource contract duplicates {action}")
            contract[action] = resource_kinds
    return contract


AWS_EC2_ACTION_RESOURCE_CONTRACT = action_resource_contract(
    (
        (
            ("*",),
            (
                "ec2:DescribeAccountAttributes",
                "ec2:DescribeAddresses",
                "ec2:DescribeAvailabilityZones",
                "ec2:DescribeFlowLogs",
                "ec2:DescribeImages",
                "ec2:DescribeIamInstanceProfileAssociations",
                "ec2:DescribeInstanceAttribute",
                "ec2:DescribeInstanceCreditSpecifications",
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceStatus",
                "ec2:DescribeInstanceTypeOfferings",
                "ec2:DescribeInstanceTypes",
                "ec2:DescribeInternetGateways",
                "ec2:DescribeNatGateways",
                "ec2:DescribeNetworkAcls",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeRegions",
                "ec2:DescribeRouteTables",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSecurityGroupRules",
                "ec2:DescribeSubnets",
                "ec2:DescribeTags",
                "ec2:DescribeVolumes",
                "ec2:DescribeVolumeAttribute",
                "ec2:DescribeVolumesModifications",
                "ec2:DescribeVpcAttribute",
                "ec2:DescribeVpcEndpointServiceConfigurations",
                "ec2:DescribeVpcEndpointServicePermissions",
                "ec2:DescribeVpcEndpointServices",
                "ec2:DescribeVpcEndpoints",
                "ec2:DescribeVpcs",
            ),
        ),
        (("elastic-ip",), ("ec2:AllocateAddress", "ec2:DisassociateAddress", "ec2:ReleaseAddress")),
        (("route-table", "subnet"), ("ec2:AssociateRouteTable", "ec2:DisassociateRouteTable", "ec2:ReplaceRouteTableAssociation")),
        (("internet-gateway", "vpc"), ("ec2:AttachInternetGateway", "ec2:DetachInternetGateway")),
        (("network-interface", "instance"), ("ec2:AttachNetworkInterface", "ec2:DetachNetworkInterface")),
        (("volume", "instance"), ("ec2:AttachVolume", "ec2:DetachVolume")),
        (
            ("security-group",),
            (
                "ec2:AuthorizeSecurityGroupEgress",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:DeleteSecurityGroup",
                "ec2:RevokeSecurityGroupEgress",
                "ec2:RevokeSecurityGroupIngress",
            ),
        ),
        (("vpc-flow-log", "vpc"), ("ec2:CreateFlowLogs",)),
        (("internet-gateway",), ("ec2:CreateInternetGateway", "ec2:DeleteInternetGateway")),
        (("natgateway", "subnet", "elastic-ip"), ("ec2:CreateNatGateway",)),
        (("natgateway",), ("ec2:DeleteNatGateway",)),
        (("network-acl", "vpc"), ("ec2:CreateNetworkAcl",)),
        (
            ("network-acl",),
            (
                "ec2:CreateNetworkAclEntry",
                "ec2:DeleteNetworkAcl",
                "ec2:DeleteNetworkAclEntry",
                "ec2:ReplaceNetworkAclEntry",
            ),
        ),
        (("network-acl", "subnet"), ("ec2:ReplaceNetworkAclAssociation",)),
        (("network-interface", "subnet", "security-group"), ("ec2:CreateNetworkInterface",)),
        (("network-interface",), ("ec2:DeleteNetworkInterface", "ec2:ModifyNetworkInterfaceAttribute")),
        (("route-table",), ("ec2:CreateRoute", "ec2:DeleteRoute", "ec2:DeleteRouteTable", "ec2:ReplaceRoute")),
        (("route-table", "vpc"), ("ec2:CreateRouteTable",)),
        (("security-group", "vpc"), ("ec2:CreateSecurityGroup",)),
        (("subnet", "vpc"), ("ec2:CreateSubnet",)),
        (("subnet",), ("ec2:DeleteSubnet", "ec2:ModifySubnetAttribute")),
        (
            (
                "elastic-ip",
                "instance",
                "internet-gateway",
                "natgateway",
                "network-acl",
                "network-interface",
                "route-table",
                "security-group",
                "subnet",
                "volume",
                "vpc",
                "vpc-endpoint",
                "vpc-endpoint-service",
                "vpc-flow-log",
            ),
            ("ec2:CreateTags", "ec2:DeleteTags"),
        ),
        (("volume",), ("ec2:CreateVolume", "ec2:DeleteVolume")),
        (("vpc",), ("ec2:CreateVpc", "ec2:DeleteVpc", "ec2:ModifyVpcAttribute")),
        (("vpc-endpoint", "vpc", "subnet"), ("ec2:CreateVpcEndpoint",)),
        (("vpc-endpoint",), ("ec2:DeleteVpcEndpoints", "ec2:ModifyVpcEndpoint")),
        (("vpc-endpoint-service",), ("ec2:CreateVpcEndpointServiceConfiguration", "ec2:DeleteVpcEndpointServiceConfigurations", "ec2:ModifyVpcEndpointServiceConfiguration")),
        (("vpc-flow-log",), ("ec2:DeleteFlowLogs",)),
        (("instance",), ("ec2:ModifyInstanceAttribute", "ec2:RebootInstances", "ec2:TerminateInstances")),
        (("image", "subnet", "security-group", "instance", "volume", "network-interface"), ("ec2:RunInstances",)),
    )
)

AWS_ELBV2_ACTION_RESOURCE_CONTRACT = action_resource_contract(
    (
        (
            ("*",),
            (
                "elasticloadbalancing:DescribeAccountLimits",
                "elasticloadbalancing:DescribeListenerAttributes",
                "elasticloadbalancing:DescribeListeners",
                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeTags",
                "elasticloadbalancing:DescribeTargetGroupAttributes",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeTargetHealth",
            ),
        ),
        (("*",), ("elasticloadbalancing:AddTags",)),
        (("load-balancer",), ("elasticloadbalancing:CreateListener", "elasticloadbalancing:CreateLoadBalancer", "elasticloadbalancing:DeleteLoadBalancer", "elasticloadbalancing:ModifyLoadBalancerAttributes", "elasticloadbalancing:SetSubnets")),
        (("target-group",), ("elasticloadbalancing:CreateTargetGroup", "elasticloadbalancing:DeleteTargetGroup", "elasticloadbalancing:DeregisterTargets", "elasticloadbalancing:ModifyTargetGroup", "elasticloadbalancing:ModifyTargetGroupAttributes", "elasticloadbalancing:RegisterTargets")),
        (("listener",), ("elasticloadbalancing:DeleteListener", "elasticloadbalancing:ModifyListenerAttributes")),
    )
)

AWS_IAM_ACTION_RESOURCE_CONTRACT = action_resource_contract(
    (
        (("*",), ("iam:GetAccountSummary", "iam:SimulateCustomPolicy")),
        (("policy-source",), ("iam:SimulatePrincipalPolicy",)),
        (("role",), ("iam:CreateRole", "iam:DeleteRole", "iam:DeleteRolePolicy", "iam:DetachRolePolicy", "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies", "iam:ListInstanceProfilesForRole", "iam:ListRolePolicies", "iam:ListRoleTags", "iam:PutRolePolicy", "iam:TagRole", "iam:UntagRole", "iam:UpdateAssumeRolePolicy")),
        (("instance-profile",), ("iam:AddRoleToInstanceProfile", "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile", "iam:GetInstanceProfile", "iam:ListInstanceProfileTags", "iam:RemoveRoleFromInstanceProfile", "iam:TagInstanceProfile", "iam:UntagInstanceProfile")),
        (("passed-role",), ("iam:PassRole",)),
    )
)

AWS_LOGS_ACTION_RESOURCE_CONTRACT = action_resource_contract(
    (
        (("*",), ("logs:DescribeLogGroups",)),
        (("log-group",), ("logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:DeleteRetentionPolicy", "logs:FilterLogEvents", "logs:ListTagsForResource", "logs:PutRetentionPolicy", "logs:TagResource", "logs:UntagResource")),
    )
)

AWS_SSM_ACTION_RESOURCE_CONTRACT = action_resource_contract(
    (
        (("parameter",), ("ssm:AddTagsToResource", "ssm:DeleteParameter", "ssm:GetParameter", "ssm:ListTagsForResource", "ssm:PutParameter", "ssm:RemoveTagsFromResource")),
        (("*",), ("ssm:CancelCommand", "ssm:DescribeInstanceInformation", "ssm:DescribeParameters", "ssm:GetCommandInvocation")),
        (("instance", "document"), ("ssm:SendCommand",)),
    )
)

AWS_KMS_ACTION_RESOURCE_CONTRACT = action_resource_contract(
    ((('kms-key',), ("kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey", "kms:GetKeyPolicy")),)
)

AWS_S3_ACTION_RESOURCE_CONTRACT = action_resource_contract(
    (
        (("*",), ("s3:ListAllMyBuckets",)),
        (("bucket",), ("s3:CreateBucket", "s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:GetAccelerateConfiguration", "s3:GetBucketAcl", "s3:GetBucketCORS", "s3:GetBucketLocation", "s3:GetBucketLogging", "s3:GetBucketNotification", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketOwnershipControls", "s3:GetBucketPolicy", "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock", "s3:GetBucketRequestPayment", "s3:GetBucketTagging", "s3:GetBucketVersioning", "s3:GetBucketWebsite", "s3:GetEncryptionConfiguration", "s3:GetLifecycleConfiguration", "s3:GetReplicationConfiguration", "s3:ListBucket", "s3:ListBucketVersions", "s3:PutBucketOwnershipControls", "s3:PutBucketPolicy", "s3:PutBucketPublicAccessBlock", "s3:PutBucketTagging", "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration")),
        (("object",), ("s3:DeleteObject", "s3:DeleteObjectVersion", "s3:GetObject", "s3:GetObjectAttributes", "s3:GetObjectTagging", "s3:PutObject", "s3:PutObjectTagging")),
    )
)

AWS_MISC_ACTION_RESOURCE_CONTRACT = action_resource_contract(
    (
        (("quota",), ("servicequotas:GetServiceQuota",)),
        (("*",), ("tag:GetResources",)),
    )
)

AWS_OPERATOR_ACTION_RESOURCE_CONTRACT = {
    **AWS_EC2_ACTION_RESOURCE_CONTRACT,
    **AWS_ELBV2_ACTION_RESOURCE_CONTRACT,
    **AWS_IAM_ACTION_RESOURCE_CONTRACT,
    **AWS_LOGS_ACTION_RESOURCE_CONTRACT,
    **AWS_SSM_ACTION_RESOURCE_CONTRACT,
    **AWS_KMS_ACTION_RESOURCE_CONTRACT,
    **AWS_S3_ACTION_RESOURCE_CONTRACT,
    **AWS_MISC_ACTION_RESOURCE_CONTRACT,
}
if set(AWS_OPERATOR_ACTION_RESOURCE_CONTRACT) != set(AWS_OPERATOR_ACTIONS):
    raise RuntimeError(
        "AWS operator action/resource contract does not exactly match AWS_OPERATOR_ACTIONS"
    )

AWS_FLOW_LOG_DELIVERY_ACTIONS = (
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:DescribeLogGroups",
    "logs:DescribeLogStreams",
    "logs:PutLogEvents",
)

AWS_REGIONAL_QUOTA_CONTRACT = {
    "cloudwatch-log-groups": ("logs", "L-C7B9AAAB", "Log groups"),
    "elastic-ips": ("ec2", "L-0263D0A3", "Elastic IP addresses per Region"),
    "gateway-load-balancer-endpoints-per-vpc": (
        "vpc",
        "L-29B6F2EB",
        "Interface VPC endpoints per VPC",
    ),
    "nat-gateways-per-availability-zone": ("vpc", "L-FE5A380F", "NAT gateways per Availability Zone"),
    "standard-vcpus": (
        "ec2",
        "L-1216C47A",
        "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances",
    ),
    "target-groups": ("elasticloadbalancing", "L-B22855CB", "Target Groups per Region"),
    "vpcs": ("vpc", "L-F678F1CE", "VPCs per Region"),
}

AWS_ELBV2_ACCOUNT_LIMIT_CONTRACT = {
    "gateway-load-balancers": "gateway-load-balancers",
    "gateway-load-balancers-per-vpc": "gateway-load-balancers-per-vpc",
    "geneve-target-groups": "geneve-target-groups",
    "targets-per-availability-zone-per-gateway-load-balancer": (
        "targets-per-availability-zone-per-gateway-load-balancer"
    ),
}

AWS_STRUCTURAL_CAPACITY_CONTRACT = {
    "flow-logs-per-resource": (
        "ec2",
        "Flow logs per resource",
        10,
        "documented-default-lower-bound",
    ),
    "listeners-per-gateway-load-balancer": (
        "elasticloadbalancing",
        "Listeners per Gateway Load Balancer",
        1,
        "documented-structural-limit",
    ),
    "targets-per-gateway-load-balancer": (
        "elasticloadbalancing",
        "Targets per Gateway Load Balancer",
        300,
        "documented-structural-limit",
    ),
    "vpc-endpoint-services": (
        "ec2",
        "VPC endpoint services per Region",
        50,
        "documented-default-lower-bound",
    ),
}

AWS_GLOBAL_QUOTA_CONTRACT = {
    "s3-artifact-buckets": ("s3", "L-DC2B2D3D", "General purpose buckets"),
}

AWS_GLOBAL_QUOTA_CONTROL_REGIONS = {
    "aws": "us-east-1",
}

AWS_PARTITION_DNS_SUFFIXES = {
    "aws": "amazonaws.com",
}

AWS_IAM_CAPACITY_CONTRACT = {
    "instance-profiles": ("InstanceProfiles", "InstanceProfilesQuota", 4),
    "roles": ("Roles", "RolesQuota", 5),
}


def redact(value: str) -> str:
    result = value
    result = SECRET_PATTERNS[0].sub("[REDACTED_TAILSCALE_KEY]", result)
    result = SECRET_PATTERNS[1].sub(r"\1\2[REDACTED]", result)
    result = SECRET_PATTERNS[2].sub("[REDACTED_AWS_ACCESS_KEY]", result)
    return result


def validate_canonical_utc_timestamp(value: Any, field: str) -> str:
    if not isinstance(value, str) or not CANONICAL_UTC_TIMESTAMP_RE.fullmatch(value):
        raise LifecycleError(f"{field} must be canonical UTC RFC3339 ending Z")
    try:
        parsed = dt.datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        raise LifecycleError(f"{field} must be canonical UTC RFC3339 ending Z") from None
    if parsed.tzinfo != dt.timezone.utc or parsed.isoformat(timespec="seconds").replace("+00:00", "Z") != value:
        raise LifecycleError(f"{field} must be canonical UTC RFC3339 ending Z")
    return value


class LifecycleError(RuntimeError):
    pass


class ConcurrentLifecycleError(LifecycleError):
    """A durable compare-and-swap collision owned by another lifecycle process."""

    cleanup_authorized = False


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
_CONCURRENT_PREPARE_RUNS: set[pathlib.Path] = set()
_CONCURRENT_PREPARE_RUNS_GUARD = threading.Lock()


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
    def __init__(
        self,
        tailnet: str,
        client_id: str,
        client_secret: str,
        transport: HTTPTransport,
        *,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not client_id or not client_secret:
            raise LifecycleError("scoped Tailscale OAuth credentials are required in protected environment variables")
        self.tailnet = tailnet
        self.client_id = client_id
        self.client_secret = client_secret
        self.transport = transport
        self.clock = clock
        self._token: str | None = None
        self._token_expires_at: float | None = None
        self._token_refresh_margin: float | None = None
        self.base_url = "https://api.tailscale.com/api/v2"

    def _invalidate_token(self) -> None:
        self._token = None
        self._token_expires_at = None
        self._token_refresh_margin = None

    def _transport_request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None,
        body: bytes | None,
        operation: str,
    ) -> tuple[int, bytes]:
        try:
            response = self.transport.request(method, url, headers=headers, body=body)
        except Exception:
            raise LifecycleError(f"{operation} transport failed") from None
        if (
            not isinstance(response, tuple)
            or len(response) != 2
            or isinstance(response[0], bool)
            or not isinstance(response[0], int)
            or not isinstance(response[1], bytes)
        ):
            raise LifecycleError(f"{operation} transport returned an invalid response")
        return response

    def _oauth_token(self) -> str:
        now = self.clock()
        if not isinstance(now, (int, float)) or isinstance(now, bool) or not math.isfinite(float(now)):
            raise LifecycleError("Tailscale OAuth monotonic clock returned an invalid value")
        if (
            self._token
            and self._token_expires_at is not None
            and self._token_refresh_margin is not None
            and float(now) < self._token_expires_at - self._token_refresh_margin
        ):
            return self._token
        self._invalidate_token()
        basic = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
        status, body = self._transport_request(
            "POST",
            f"{self.base_url}/oauth/token",
            headers={
                "Authorization": f"Basic {basic}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body=urllib.parse.urlencode({"grant_type": "client_credentials"}).encode(),
            operation="obtain Tailscale OAuth token",
        )
        response = self._decode(status, body, "obtain OAuth token")
        token = response.get("access_token")
        if not isinstance(token, str) or not token:
            raise LifecycleError("Tailscale OAuth response omitted access_token")
        raw_expires_in = response.get("expires_in")
        if isinstance(raw_expires_in, bool):
            raise LifecycleError("Tailscale OAuth response has an invalid expires_in")
        if isinstance(raw_expires_in, int):
            expires_in = raw_expires_in
        elif isinstance(raw_expires_in, str) and re.fullmatch(r"[1-9][0-9]*", raw_expires_in):
            try:
                expires_in = int(raw_expires_in)
            except ValueError:
                raise LifecycleError("Tailscale OAuth response has an invalid expires_in") from None
        else:
            raise LifecycleError("Tailscale OAuth response has an invalid expires_in")
        if expires_in <= 0 or expires_in > TAILSCALE_OAUTH_MAX_EXPIRES_IN_SECONDS:
            raise LifecycleError("Tailscale OAuth response has an invalid expires_in")
        obtained_at = self.clock()
        if (
            not isinstance(obtained_at, (int, float))
            or isinstance(obtained_at, bool)
            or not math.isfinite(float(obtained_at))
        ):
            raise LifecycleError("Tailscale OAuth monotonic clock returned an invalid value")
        self._token = token
        self._token_expires_at = float(obtained_at) + expires_in
        self._token_refresh_margin = min(TAILSCALE_OAUTH_REFRESH_MARGIN_SECONDS, expires_in / 10)
        return token

    def _authorized_request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, bytes]:
        for attempt in range(2):
            request_headers = dict(headers or {})
            request_headers["Authorization"] = f"Bearer {self._oauth_token()}"
            status, response = self._transport_request(
                method,
                f"{self.base_url}{path}",
                headers=request_headers,
                body=body,
                operation=f"Tailscale API {method} {path}",
            )
            if status != 401 or attempt == 1:
                return status, response
            self._invalidate_token()
        raise AssertionError("unreachable Tailscale OAuth retry state")

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        status, response = self._authorized_request(
            method,
            path,
            headers={"Content-Type": "application/json"},
            body=body,
        )
        return self._decode(status, response, f"Tailscale API {method} {path}")

    @staticmethod
    def _decode(status: int, body: bytes, operation: str) -> dict[str, Any]:
        if isinstance(status, bool) or not isinstance(status, int):
            raise LifecycleError(f"{operation} returned an invalid HTTP status")
        if status < 200 or status >= 300:
            raise LifecycleError(f"{operation} failed with HTTP {status}")
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
        path = f"/tailnet/{urllib.parse.quote(self.tailnet, safe='')}/acl"
        status, body = self._authorized_request(
            "GET",
            path,
            headers={"Accept": "application/hujson"},
        )
        if status < 200 or status >= 300:
            raise LifecycleError(f"read Tailnet policy failed with HTTP {status}")
        try:
            return body.decode()
        except UnicodeDecodeError:
            raise LifecycleError("read Tailnet policy returned invalid UTF-8") from None

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
        status, body = self._authorized_request(
            "DELETE",
            path,
        )
        if status == 404 or 200 <= status < 300:
            return
        self._decode(status, body, "revoke Tailscale auth key")

    def delete_device(self, device_id: str) -> None:
        path = f"/device/{urllib.parse.quote(device_id, safe='')}"
        status, body = self._authorized_request(
            "DELETE",
            path,
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
    site_cidrs: dict[str, list[str]],
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
        for source in site_cidrs[source_site]:
            for destination in site_cidrs[destination_site]:
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


def normalize_e2e_load_profile(
    value: Any,
    *,
    loaded_at: dt.datetime,
    enforce_approval_time: bool,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LifecycleError("e2e_load_profile must be a required object")
    expected = set(E2E_LOAD_PROFILE_FIELDS)
    extra = set(value) - expected
    if extra:
        raise LifecycleError(f"e2e_load_profile has unsupported fields: {sorted(extra)}")
    if set(value) != expected:
        raise LifecycleError("e2e_load_profile must contain every required load threshold")
    profile_id = value["profile_id"]
    if not isinstance(profile_id, str) or not E2E_LOAD_PROFILE_ID_RE.fullmatch(profile_id):
        raise LifecycleError("e2e_load_profile.profile_id is invalid")
    approved_at = value["approved_at"]
    if not isinstance(approved_at, str) or not E2E_LOAD_PROFILE_APPROVED_AT_RE.fullmatch(approved_at):
        raise LifecycleError("e2e_load_profile.approved_at must be canonical UTC RFC3339 ending Z")
    try:
        approved = dt.datetime.fromisoformat(approved_at.removesuffix("Z") + "+00:00")
    except ValueError:
        raise LifecycleError("e2e_load_profile.approved_at must be canonical UTC RFC3339 ending Z") from None
    canonical_approval = approved.isoformat(timespec="seconds").replace("+00:00", "Z")
    if approved.tzinfo != dt.timezone.utc or canonical_approval != approved_at:
        raise LifecycleError("e2e_load_profile.approved_at must be canonical UTC RFC3339 ending Z")
    if enforce_approval_time and approved > loaded_at:
        raise LifecycleError("e2e_load_profile.approved_at must not be later than config load time")

    for name, (minimum, maximum) in E2E_LOAD_PROFILE_INTEGER_BOUNDS.items():
        candidate = value[name]
        if isinstance(candidate, bool) or not isinstance(candidate, int) or not minimum <= candidate <= maximum:
            raise LifecycleError(f"e2e_load_profile.{name} must be an integer between {minimum} and {maximum}")
    if value["safe_inner_mtu"] != 1280:
        raise LifecycleError("e2e_load_profile.safe_inner_mtu must equal 1280")
    if value["maximum_tcp_mss"] > 1240:
        raise LifecycleError("e2e_load_profile.maximum_tcp_mss must be no greater than 1240")

    for name, (minimum, maximum) in E2E_LOAD_PROFILE_NUMBER_BOUNDS.items():
        candidate = value[name]
        if isinstance(candidate, bool) or not isinstance(candidate, (int, float)):
            raise LifecycleError(f"e2e_load_profile.{name} must be a finite number")
        try:
            finite = math.isfinite(float(candidate))
        except (OverflowError, ValueError):
            finite = False
        if not finite:
            raise LifecycleError(f"e2e_load_profile.{name} must be a finite number")
        if not minimum <= float(candidate) <= maximum:
            raise LifecycleError(f"e2e_load_profile.{name} must be between {minimum:g} and {maximum:g}")
    return {name: value[name] for name in E2E_LOAD_PROFILE_FIELDS}


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
            "symmetric_topology",
            "tailnet",
            "envelope",
            "cost",
            "e2e_load_profile",
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
        loaded_at = dt.datetime.now(dt.timezone.utc)
        if enforce_future_expiry:
            if expiry <= loaded_at + dt.timedelta(minutes=30) or expiry > loaded_at + dt.timedelta(hours=24):
                raise LifecycleError("expires_at must be 30 minutes to 24 hours in the future for a new run")
        e2e_load_profile = normalize_e2e_load_profile(
            raw.get("e2e_load_profile"),
            loaded_at=loaded_at,
            enforce_approval_time=enforce_future_expiry,
        )
        backend = raw.get("backend")
        topology = raw.get("symmetric_topology")
        sites = topology.get("sites") if isinstance(topology, dict) else None
        tailnet = raw.get("tailnet")
        architecture = str(raw.get("architecture", ""))
        if not isinstance(backend, dict) or not isinstance(topology, dict) or not isinstance(sites, dict) or not isinstance(tailnet, dict):
            raise LifecycleError("backend, symmetric_topology, and tailnet objects are required")
        if set(topology) != {"version", "sites"} or topology.get("version") != 2:
            raise LifecycleError("symmetric_topology must be version 2 with exactly version and sites")
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
        if not re.fullmatch(
            r"arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+",
            str(backend["kms_key_arn"]),
        ):
            raise LifecycleError("backend.kms_key_arn must be an exact commercial-partition KMS key ARN")
        state_key = str(backend.get("state_key", f"runs/{run_id}/terraform.tfstate"))
        if state_key != f"runs/{run_id}/terraform.tfstate":
            raise LifecycleError("backend.state_key must be the unique run-owned key")
        principals = backend.get("operator_principal_arns")
        if not isinstance(principals, list) or not principals or not all(
            isinstance(value, str)
            and re.fullmatch(r"arn:aws:iam::[0-9]{12}:(?:role|user)/[^*]+", value)
            for value in principals
        ):
            raise LifecycleError(
                "backend.operator_principal_arns must list exact commercial-partition IAM role/user ARNs"
            )
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
                "vpc_cidr",
                "local_site_cidrs",
                "remote_site_cidrs",
                "workload_subnet_cidrs",
                "ingress_subnet_cidrs",
                "gwlbe_subnet_cidrs",
                "gwlb_subnet_cidrs",
                "target_subnet_cidrs",
                "management_subnet_cidr",
                "target_az_keys",
                "ingress_router_az_keys",
            )
            if set(value) - set(required):
                raise LifecycleError(f"sites.{site} has unsupported fields: {sorted(set(value) - set(required))}")
            if not all(value.get(key) for key in required):
                raise LifecycleError(f"symmetric_topology.sites.{site} is missing a required symmetric topology input")
            if not re.fullmatch(r"ami-[0-9a-f]{8,17}", str(value["ami_id"])):
                raise LifecycleError(f"sites.{site}.ami_id must be an explicit AMI ID")
            region = str(value["region"])
            kms_pattern = rf"arn:aws:kms:{re.escape(region)}:[0-9]{{12}}:key/[A-Za-z0-9-]+"
            if not re.fullmatch(kms_pattern, str(value["ssm_kms_key_arn"])):
                raise LifecycleError(
                    f"sites.{site}.ssm_kms_key_arn must be an exact commercial-partition regional KMS key ARN"
                )
            azs = value["azs"]
            if not isinstance(azs, dict) or len(azs) != 2 or not all(
                isinstance(key, str)
                and re.fullmatch(r"[a-z][a-z0-9-]{0,7}", key)
                and isinstance(zone, str)
                and zone.startswith(region)
                for key, zone in azs.items()
            ) or len(set(azs.values())) != len(azs):
                raise LifecycleError(f"symmetric_topology.sites.{site}.azs must contain exactly two unique explicit regional AZs")
            role_maps: dict[str, dict[str, str]] = {}
            for field in (
                "workload_subnet_cidrs",
                "ingress_subnet_cidrs",
                "gwlbe_subnet_cidrs",
                "gwlb_subnet_cidrs",
                "target_subnet_cidrs",
            ):
                candidate = value[field]
                if not isinstance(candidate, dict) or set(candidate) != set(azs):
                    raise LifecycleError(f"sites.{site}.{field} must use exactly the configured AZ keys")
                role_maps[field] = {str(key): str(cidr) for key, cidr in candidate.items()}
            try:
                vpc = ipaddress.ip_network(str(value["vpc_cidr"]), strict=True)
                if vpc.version != 4:
                    raise ValueError("IPv4 required")
                subnets = [
                    ipaddress.ip_network(str(value["management_subnet_cidr"]), strict=True),
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
            local = [str(cidr) for cidr in value["local_site_cidrs"]] if isinstance(value["local_site_cidrs"], list) else []
            remote = [str(cidr) for cidr in value["remote_site_cidrs"]] if isinstance(value["remote_site_cidrs"], list) else []
            workload_values = set(role_maps["workload_subnet_cidrs"].values())
            if (
                not local
                or not remote
                or len(set(local)) != len(local)
                or len(set(remote)) != len(remote)
                or set(local) != workload_values
            ):
                raise LifecycleError(f"symmetric_topology.sites.{site}.local_site_cidrs must exactly cover workload CIDRs")
            try:
                local_networks = [ipaddress.ip_network(cidr, strict=True) for cidr in local]
                remote_networks = [ipaddress.ip_network(cidr, strict=True) for cidr in remote]
            except ValueError as error:
                raise LifecycleError(f"symmetric_topology.sites.{site} contains an invalid site CIDR") from error
            if any(left.overlaps(right) for left in local_networks for right in remote_networks):
                raise LifecycleError(f"symmetric_topology.sites.{site} local and remote site CIDRs must be disjoint")
            target_az_keys = value["target_az_keys"]
            ingress_az_keys = value["ingress_router_az_keys"]
            if (
                not isinstance(target_az_keys, list)
                or not isinstance(ingress_az_keys, list)
                or set(target_az_keys) != set(azs)
                or set(ingress_az_keys) != set(azs)
            ):
                raise LifecycleError(f"symmetric_topology.sites.{site} target and ingress-router fleets must cover every AZ")
            normalized_sites[site] = {
                "region": region,
                "ami_id": str(value["ami_id"]),
                "ssm_kms_key_arn": str(value["ssm_kms_key_arn"]),
                "azs": {str(key): str(zone) for key, zone in azs.items()},
                "vpc_cidr": str(vpc),
                **role_maps,
                "management_subnet_cidr": str(value["management_subnet_cidr"]),
                "local_site_cidrs": local,
                "remote_site_cidrs": remote,
                "target_az_keys": sorted(target_az_keys),
                "ingress_router_az_keys": sorted(ingress_az_keys),
            }
            site_networks[site] = vpc
        sites = normalized_sites
        backend_partition = str(backend["kms_key_arn"]).split(":", 2)[1]
        configured_partitions = {
            backend_partition,
            *(str(value).split(":", 2)[1] for value in backend["operator_principal_arns"]),
            *(str(sites[site]["ssm_kms_key_arn"]).split(":", 2)[1] for site in ("west", "east")),
        }
        if configured_partitions != {"aws"} or backend_partition != "aws":
            raise LifecycleError(
                "backend, operator, and site ARNs must all use the commercial aws partition"
            )
        if sites["west"]["region"] == sites["east"]["region"]:
            raise LifecycleError("west and east regions must be distinct")
        if site_networks["west"].overlaps(site_networks["east"]):
            raise LifecycleError("west and east VPC CIDRs must not overlap")
        if set(sites["west"]["remote_site_cidrs"]) != set(sites["east"]["local_site_cidrs"]) or set(
            sites["east"]["remote_site_cidrs"]
        ) != set(sites["west"]["local_site_cidrs"]):
            raise LifecycleError("symmetric_topology remote_site_cidrs must exactly equal the peer local_site_cidrs")
        for key in ("name", "tag", "tag_owners"):
            if key not in tailnet:
                raise LifecycleError(f"tailnet.{key} is required")
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
            "e2e_load_profile": e2e_load_profile,
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
    def site_cidrs(self) -> dict[str, list[str]]:
        return {
            site: list(self.sites[site]["local_site_cidrs"])
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


def policy_values(value: Any, field: str) -> list[str]:
    values = [value] if isinstance(value, str) else value
    if (
        not isinstance(values, list)
        or not values
        or not all(isinstance(item, str) and item and "${" not in item for item in values)
        or len(set(values)) != len(values)
    ):
        raise LifecycleError(f"resource policy has malformed or unresolved {field}")
    return values


def decode_policy_document(value: Any, gate: str) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as error:
            raise LifecycleError(f"{gate} is not valid JSON") from error
    if not isinstance(value, dict):
        raise LifecycleError(f"{gate} is not a JSON object")
    statements = value.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements or not all(isinstance(item, dict) for item in statements):
        raise LifecycleError(f"{gate} has a malformed Statement collection")
    return {**value, "Statement": statements}


def policy_principal_matches(statement: dict[str, Any], principal: str) -> bool:
    if "NotPrincipal" in statement:
        raise LifecycleError("resource policy uses unsupported NotPrincipal semantics")
    value = statement.get("Principal")
    if value == "*":
        return True
    if not isinstance(value, dict) or not value or any(key not in {"AWS", "Service"} for key in value):
        raise LifecycleError("resource policy has a malformed Principal")
    for principal_type, principals in value.items():
        policy_values(principals, f"{principal_type} principal")
    if "AWS" not in value:
        return False
    principals = policy_values(value["AWS"], "AWS principal")
    if "*" in principals or principal in principals:
        return True
    principal_parts = principal.split(":", 5)
    if len(principal_parts) != 6:
        raise LifecycleError("resource policy evaluation received a malformed principal ARN")
    account_root = f"arn:{principal_parts[1]}:iam::{principal_parts[4]}:root"
    return account_root in principals


def policy_condition_matches(condition: Any, context: dict[str, str | list[str]]) -> bool:
    if condition is None:
        return True
    if not isinstance(condition, dict) or not condition:
        raise LifecycleError("resource policy has a malformed Condition")
    normalized_context = {
        key.lower(): [value] if isinstance(value, str) else value
        for key, value in context.items()
    }
    supported = {
        "StringEquals",
        "StringNotEquals",
        "StringLike",
        "StringNotLike",
        "ArnEquals",
        "ArnLike",
        "Bool",
        "Null",
    }
    for raw_operator, entries in condition.items():
        if not isinstance(raw_operator, str) or not isinstance(entries, dict) or not entries:
            raise LifecycleError("resource policy has a malformed condition operator")
        operator = raw_operator
        quantifier = ""
        if ":" in operator:
            prefix, operator = operator.split(":", 1)
            if prefix not in {"ForAllValues", "ForAnyValue"}:
                raise LifecycleError(f"resource policy uses unsupported condition operator {raw_operator}")
            quantifier = prefix
        if_exists = operator.endswith("IfExists")
        if if_exists:
            operator = operator.removesuffix("IfExists")
        if operator not in supported or (quantifier and operator in {"Bool", "Null"}):
            raise LifecycleError(f"resource policy uses unsupported condition operator {raw_operator}")
        for key, raw_expected in entries.items():
            if not isinstance(key, str) or not key or "${" in key:
                raise LifecycleError("resource policy has a malformed condition key")
            expected = policy_values(raw_expected, f"condition {key}")
            actual = normalized_context.get(key.lower())
            if operator == "Null":
                if len(expected) != 1 or expected[0].lower() not in {"true", "false"}:
                    raise LifecycleError(f"resource policy has a malformed Null condition for {key}")
                if ((actual is None) != (expected[0].lower() == "true")):
                    return False
                continue
            if actual is None:
                if if_exists:
                    continue
                raise LifecycleError(f"resource policy condition {key} lacks exact request context")
            if not isinstance(actual, list) or not actual or not all(isinstance(item, str) for item in actual):
                raise LifecycleError(f"resource policy request context {key} is malformed")

            if operator == "Bool":
                if any(value.lower() not in {"true", "false"} for value in [*actual, *expected]):
                    raise LifecycleError(f"resource policy has a malformed Bool condition for {key}")
                matches = [value.lower() in {candidate.lower() for candidate in expected} for value in actual]
            else:
                pattern_operator = operator in {"StringLike", "StringNotLike", "ArnLike"}
                matches = [
                    any(
                        fnmatch.fnmatchcase(value, candidate) if pattern_operator else value == candidate
                        for candidate in expected
                    )
                    for value in actual
                ]
                if operator in {"StringNotEquals", "StringNotLike"}:
                    matches = [not value for value in matches]
            if quantifier == "ForAllValues":
                matched = all(matches)
            elif quantifier == "ForAnyValue":
                matched = any(matches)
            else:
                matched = any(matches)
            if not matched:
                return False
    return True


def resource_policy_decision(
    policy: dict[str, Any],
    principal: str,
    action: str,
    resource: str,
    context: dict[str, str | list[str]],
) -> str:
    allowed = False
    for statement in policy["Statement"]:
        if statement.get("Effect") not in {"Allow", "Deny"}:
            raise LifecycleError("resource policy has a malformed Effect")
        if any(field in statement for field in ("NotAction", "NotResource")):
            raise LifecycleError("resource policy uses unsupported NotAction or NotResource semantics")
        actions = policy_values(statement.get("Action"), "Action")
        resources = policy_values(statement.get("Resource"), "Resource")
        principal_matches = policy_principal_matches(statement, principal)
        action_matches = any(fnmatch.fnmatchcase(action.lower(), pattern.lower()) for pattern in actions)
        resource_matches = any(fnmatch.fnmatchcase(resource, pattern) for pattern in resources)
        if not principal_matches or not action_matches or not resource_matches:
            continue
        if not policy_condition_matches(statement.get("Condition"), context):
            continue
        if statement["Effect"] == "Deny":
            return "explicitDeny"
        allowed = True
    return "allowed" if allowed else "implicitDeny"


def exact_policy_condition(
    condition: Any,
    key: str,
    expected: str,
    operators: tuple[str, ...],
) -> bool:
    if not isinstance(condition, dict):
        return False
    values: list[str] = []
    for operator in operators:
        entries = condition.get(operator)
        if entries is None:
            continue
        if not isinstance(entries, dict):
            return False
        for candidate_key, value in entries.items():
            if isinstance(candidate_key, str) and candidate_key.lower() == key.lower():
                values.extend(policy_values(value, f"condition {candidate_key}"))
    return values == [expected]


def kms_key_policy_identity_decision(
    policy: dict[str, Any],
    principal: str,
    action: str,
    context: dict[str, str | list[str]],
) -> tuple[str, str | None]:
    effective = resource_policy_decision(policy, principal, action, "*", context)
    if effective == "explicitDeny":
        return "explicitDeny", None
    principal_parts = principal.split(":", 5)
    if len(principal_parts) != 6:
        raise LifecycleError("KMS key policy evaluation received a malformed principal ARN")
    account_root = f"arn:{principal_parts[1]}:iam::{principal_parts[4]}:root"
    for statement in policy["Statement"]:
        if statement.get("Effect") != "Allow":
            continue
        actions = policy_values(statement.get("Action"), "Action")
        resources = policy_values(statement.get("Resource"), "Resource")
        if not any(fnmatch.fnmatchcase(action.lower(), pattern.lower()) for pattern in actions) or "*" not in resources:
            continue
        raw_principal = statement.get("Principal")
        if raw_principal == "*":
            principals = ["*"]
        elif isinstance(raw_principal, dict) and "AWS" in raw_principal:
            principals = policy_values(raw_principal["AWS"], "AWS principal")
        else:
            continue
        if principal in principals:
            mode = "direct"
        elif account_root in principals:
            mode = "account-root-delegation"
        elif "*" in principals:
            if not (
                exact_policy_condition(
                    statement.get("Condition"),
                    "aws:PrincipalArn",
                    principal,
                    ("ArnEquals", "ArnLike"),
                )
                and exact_policy_condition(
                    statement.get("Condition"),
                    "kms:ViaService",
                    str(context["kms:ViaService"]),
                    ("StringEquals",),
                )
                and exact_policy_condition(
                    statement.get("Condition"),
                    "kms:EncryptionContext:PARAMETER_ARN",
                    str(context["kms:EncryptionContext:PARAMETER_ARN"]),
                    ("StringEquals", "ArnEquals"),
                )
            ):
                continue
            mode = "exact-wildcard-principal"
        else:
            continue
        if policy_condition_matches(statement.get("Condition"), context):
            return "allowed", mode
    return "implicitDeny", None


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
        partition = str(kms_key).split(":", 2)[1]
        dns_suffix = AWS_PARTITION_DNS_SUFFIXES[partition]
        self.aws.json(["s3api", "head-bucket", "--bucket", bucket], region=region)
        location = self.aws.json(["s3api", "get-bucket-location", "--bucket", bucket], region=region)
        actual_region = location.get("LocationConstraint") or "us-east-1"
        if actual_region != region:
            raise LifecycleError("backend bucket region differs from the configured region")
        versioning = self.aws.json(["s3api", "get-bucket-versioning", "--bucket", bucket], region=region)
        if versioning.get("Status") != "Enabled":
            raise LifecycleError("backend bucket versioning must be Enabled")
        encryption = self.aws.json(["s3api", "get-bucket-encryption", "--bucket", bucket], region=region)
        encryption_configuration = encryption.get("ServerSideEncryptionConfiguration")
        rules = encryption_configuration.get("Rules") if isinstance(encryption_configuration, dict) else None
        if not isinstance(rules, list) or not rules or not all(isinstance(rule, dict) for rule in rules):
            raise LifecycleError("backend bucket must default to the exact operator-owned KMS key")
        matching_rules: list[dict[str, Any]] = []
        for rule in rules:
            default = rule.get("ApplyServerSideEncryptionByDefault")
            if not isinstance(default, dict) or type(rule.get("BucketKeyEnabled")) is not bool:
                raise LifecycleError("backend bucket returned malformed default encryption metadata")
            if default.get("SSEAlgorithm") == "aws:kms" and default.get("KMSMasterKeyID") == kms_key:
                matching_rules.append(rule)
        if len(matching_rules) != 1:
            raise LifecycleError("backend bucket must default to the exact operator-owned KMS key")
        if matching_rules[0]["BucketKeyEnabled"] is not True:
            raise LifecycleError("backend bucket must enable S3 Bucket Keys for the fixed backend contract")
        public = self.aws.json(["s3api", "get-public-access-block", "--bucket", bucket], region=region)
        block = public.get("PublicAccessBlockConfiguration", {})
        required = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
        if not all(block.get(key) is True for key in required):
            raise LifecycleError("backend bucket public access block must be fully enabled")
        policy_status = self.aws.json(["s3api", "get-bucket-policy-status", "--bucket", bucket], region=region)
        if policy_status.get("PolicyStatus", {}).get("IsPublic") is not False:
            raise LifecycleError("backend bucket policy must be present and non-public")
        policy_response = self.aws.json(["s3api", "get-bucket-policy", "--bucket", bucket], region=region)
        bucket_policy = decode_policy_document(policy_response.get("Policy"), "backend bucket policy")
        bucket_arn = f"arn:{partition}:s3:::{bucket}"
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
        insecure_requests = [
            *((action, bucket_arn) for action in BACKEND_BUCKET_ACTIONS),
            *(
                (action, object_arn)
                for object_arn, actions in object_actions.items()
                for action in actions
            ),
        ]
        for principal in config.backend["operator_principal_arns"]:
            insecure_context = {
                "aws:PrincipalArn": principal,
                "aws:SecureTransport": "false",
                "aws:RequestedRegion": str(region),
            }
            if any(
                resource_policy_decision(
                    bucket_policy,
                    principal,
                    action,
                    resource,
                    insecure_context,
                )
                != "explicitDeny"
                for action, resource in insecure_requests
            ):
                raise LifecycleError(
                    "backend bucket policy must deny insecure transport for every required "
                    f"action and resource for configured operator {principal}"
                )

        def require_policy_decision(
            policy: dict[str, Any],
            principal: str,
            action: str,
            resource: str,
            context: dict[str, str | list[str]],
            message: str,
        ) -> None:
            decision = resource_policy_decision(policy, principal, action, resource, context)
            if decision == "explicitDeny":
                raise LifecycleError(f"{message}; an applicable statement explicitly denies the request")
            if decision != "allowed":
                raise LifecycleError(message)

        for principal in config.backend["operator_principal_arns"]:
            for action in BACKEND_BUCKET_ACTIONS:
                contexts = [
                    {
                        "aws:PrincipalArn": principal,
                        "aws:SecureTransport": "true",
                        "aws:RequestedRegion": str(region),
                    }
                ]
                if action in {"s3:ListBucket", "s3:ListBucketVersions"}:
                    contexts = [
                        {**contexts[0], "s3:prefix": key}
                        for key in (str(config.backend["state_key"]), config.lock_key, config.manifest_key)
                    ]
                for context in contexts:
                    require_policy_decision(
                        bucket_policy,
                        principal,
                        action,
                        bucket_arn,
                        context,
                        f"backend policy omits {action} on the backend bucket for {principal}",
                    )
            for object_arn, actions in object_actions.items():
                for action in actions:
                    context = {
                        "aws:PrincipalArn": principal,
                        "aws:SecureTransport": "true",
                        "aws:RequestedRegion": str(region),
                    }
                    if action == "s3:PutObject":
                        context.update(
                            {
                                "s3:x-amz-server-side-encryption": "aws:kms",
                                "s3:x-amz-server-side-encryption-aws-kms-key-id": str(kms_key),
                            }
                        )
                    if object_arn.endswith(f"/{config.manifest_key}") and (
                        action.startswith("s3:Put") or action == "s3:GetObject"
                    ):
                        ownership_tags = {
                            "EnvelopeRun": config.run_id,
                            "ExpiresAt": config.expires_at,
                        }
                        tag_namespace = "s3:RequestObjectTag" if action.startswith("s3:Put") else "s3:ExistingObjectTag"
                        context.update({f"{tag_namespace}/{key}": value for key, value in ownership_tags.items()})
                    require_policy_decision(
                        bucket_policy,
                        principal,
                        action,
                        object_arn,
                        context,
                        f"backend policy omits {action} for a run-owned object",
                    )

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
        key_policy = decode_policy_document(key_policy_response.get("Policy"), "backend KMS key policy")
        for principal in config.backend["operator_principal_arns"]:
            for action in BACKEND_KMS_ACTIONS:
                contexts = [
                    {
                        "aws:PrincipalArn": principal,
                        "aws:RequestedRegion": str(region),
                    }
                ]
                if action in {"kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"}:
                    contexts = [
                        {
                            **contexts[0],
                            "kms:ViaService": f"s3.{region}.{dns_suffix}",
                            "kms:EncryptionContextKeys": ["aws:s3:arn"],
                            "kms:EncryptionContext:aws:s3:arn": bucket_arn,
                        }
                    ]
                for context in contexts:
                    require_policy_decision(
                        key_policy,
                        principal,
                        action,
                        "*",
                        context,
                        f"backend KMS key policy omits {action} for a protected operator",
                    )
        if require_empty:
            for key in (config.backend["state_key"], config.lock_key, config.manifest_key):
                if exact_object_versions(self.aws, bucket=bucket, key=key, region=region):
                    raise LifecycleError(f"run-owned backend key has a historical version or delete marker: {key}")


def validate_aws_metadata(config: RunConfig, aws: AwsCLI) -> dict[str, dict[str, int]]:
    expected = ARCHITECTURES[config.architecture]
    appliance_type = str(config.raw.get("instance_type", ""))
    test_type = str(config.raw.get("test_instance_type", ""))
    if not appliance_type or not test_type:
        raise LifecycleError("instance_type and test_instance_type are required")
    vcpus: dict[str, dict[str, int]] = {}
    for site in ("west", "east"):
        region = config.sites[site]["region"]
        image_id = config.sites[site]["ami_id"]
        response = aws.json(["ec2", "describe-images", "--image-ids", image_id], region=region)
        images = response.get("Images")
        if not isinstance(images, list) or len(images) != 1 or not isinstance(images[0], dict):
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
        type_response = aws.json(
            ["ec2", "describe-instance-types", "--instance-types", appliance_type, test_type], region=region
        )
        types = type_response.get("InstanceTypes")
        if not isinstance(types, list) or not all(isinstance(value, dict) for value in types):
            raise LifecycleError(f"{site} instance type metadata returned an invalid schema")
        requested_types = {appliance_type, test_type}
        if len(types) != len(requested_types) or any(
            not isinstance(value.get("InstanceType"), str) for value in types
        ):
            raise LifecycleError(f"{site} instance type metadata did not return each exact requested type")
        by_name = {str(value["InstanceType"]): value for value in types}
        if len(by_name) != len(types) or set(by_name) != requested_types:
            raise LifecycleError(f"{site} instance type metadata did not return each exact requested type")
        vcpus[region] = {}
        for selected in (appliance_type, test_type):
            processor = by_name[selected].get("ProcessorInfo")
            supported = processor.get("SupportedArchitectures") if isinstance(processor, dict) else None
            if not isinstance(supported, list) or not all(isinstance(value, str) for value in supported) or expected not in supported:
                raise LifecycleError(f"{site} instance type {selected} does not support {expected}")
            cpu = by_name[selected].get("VCpuInfo")
            default_vcpus = cpu.get("DefaultVCpus") if isinstance(cpu, dict) else None
            if isinstance(default_vcpus, bool) or not isinstance(default_vcpus, int) or default_vcpus <= 0:
                raise LifecycleError(f"{site} instance type {selected} omitted a positive default vCPU count")
            vcpus[region][selected] = default_vcpus
    return vcpus


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
    if variables.get("e2e_load_profile") != config.raw["e2e_load_profile"]:
        raise LifecycleError("cleanup manifest load profile differs from the requested run identity")
    account_id = str(manifest.get("aws_account_id", ""))
    if not re.fullmatch(r"[0-9]{12}", account_id):
        raise LifecycleError("cleanup manifest AWS account identity is invalid")
    validate_aws_preflight_summary(manifest.get("aws_preflight"), config, account_id)
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
    phase = manifest.get("phase")
    if not isinstance(phase, str) or not phase:
        raise LifecycleError("cleanup manifest lifecycle phase is invalid")
    active_apply_phases = {
        "apply_claimed",
        "replacement_device_retirement_started",
        "replacement_device_retired",
        "apply_started",
    }
    applied_phases = {"applied", "readiness_started", "readiness_failed", "ready"}
    saved_plan = manifest.get("saved_plan")
    if saved_plan is not None:
        if not isinstance(saved_plan, dict):
            raise LifecycleError("cleanup manifest saved plan is invalid")
        apply_started = saved_plan.get("apply_started")
        applied = saved_plan.get("applied")
        if type(apply_started) is not bool or type(applied) is not bool or applied and not apply_started:
            raise LifecycleError("cleanup manifest saved plan has an invalid apply state")
        saved_applied_at = saved_plan.get("applied_at")
        if applied:
            validate_canonical_utc_timestamp(saved_applied_at, "saved_plan.applied_at")
        elif saved_applied_at is not None:
            raise LifecycleError("cleanup manifest has saved_plan.applied_at before a successful apply")
    if phase in active_apply_phases:
        if not isinstance(saved_plan, dict) or saved_plan.get("apply_started") is not True or saved_plan.get("applied") is not False:
            raise LifecycleError("cleanup manifest active apply phase has no exact saved-plan claim")
        validate_canonical_utc_timestamp(manifest.get("apply_claimed_at"), "apply_claimed_at")
    elif "apply_claimed_at" in manifest:
        raise LifecycleError("cleanup manifest retains a stale active apply claim")
    if phase in applied_phases and (
        not isinstance(saved_plan, dict)
        or saved_plan.get("apply_started") is not True
        or saved_plan.get("applied") is not True
    ):
        raise LifecycleError("cleanup manifest applied lifecycle phase lacks successful saved-plan evidence")
    if phase == "apply_failed" and (
        not isinstance(saved_plan, dict)
        or saved_plan.get("apply_started") is not True
        or saved_plan.get("applied") is not False
    ):
        raise LifecycleError("cleanup manifest failed apply phase lacks exact saved-plan evidence")
    if "applied_at" in manifest:
        raise LifecycleError("cleanup manifest applied timestamp must live only under saved_plan")
    e2e = manifest.get("e2e")
    if phase in {"e2e_running", "e2e_passed", "e2e_failed"} and not isinstance(e2e, dict):
        raise LifecycleError("cleanup manifest E2E phase lacks its exact durable claim")
    if isinstance(e2e, dict):
        base_fields = {"claim_id", "output_sha256", "started_at"}
        terminal_fields = base_fields | {"finished_at", "passed"}
        e2e_fields = set(e2e)
        if e2e_fields != base_fields and e2e_fields != terminal_fields:
            raise LifecycleError("cleanup manifest E2E claim has an invalid schema")
        if (
            not isinstance(e2e.get("claim_id"), str)
            or not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                e2e["claim_id"],
            )
            or not isinstance(e2e.get("output_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", e2e["output_sha256"])
        ):
            raise LifecycleError("cleanup manifest E2E claim identity is invalid")
        validate_canonical_utc_timestamp(e2e.get("started_at"), "e2e.started_at")
        if e2e_fields == terminal_fields:
            validate_canonical_utc_timestamp(e2e.get("finished_at"), "e2e.finished_at")
            if type(e2e.get("passed")) is not bool:
                raise LifecycleError("cleanup manifest E2E result is invalid")
        if phase == "e2e_running" and e2e_fields != base_fields:
            raise LifecycleError("cleanup manifest running E2E claim already has terminal fields")
        if phase in {"e2e_passed", "e2e_failed"} and (
            e2e_fields != terminal_fields or e2e["passed"] != (phase == "e2e_passed")
        ):
            raise LifecycleError("cleanup manifest terminal E2E phase differs from its result")
    serialized = json.dumps(manifest)
    if "tskey-" in serialized.lower() or "oauth_client_secret" in serialized.lower():
        raise LifecycleError("cleanup manifest contains prohibited secret material")


def aws_caller_identity(aws: AwsCLI) -> dict[str, str]:
    identity = aws.json(["sts", "get-caller-identity"])
    account, arn, user_id = identity.get("Account"), identity.get("Arn"), identity.get("UserId")
    if isinstance(arn, str) and arn.startswith("arn:") and arn.split(":", 2)[1] != "aws":
        raise LifecycleError("AWS caller identity must use the commercial aws ARN partition")
    if (
        not isinstance(account, str)
        or not re.fullmatch(r"[0-9]{12}", account)
        or not isinstance(arn, str)
        or not re.fullmatch(r"arn:aws:(?:iam|sts)::[0-9]{12}:[A-Za-z0-9+=,.@_/-]+", arn)
        or arn.split(":", 5)[4] != account
        or not isinstance(user_id, str)
        or not user_id
    ):
        raise LifecycleError("AWS caller identity returned a malformed account, ARN, or user ID")
    return {"account_id": account, "arn": arn, "user_id": user_id}


def caller_account_id(aws: AwsCLI) -> str:
    return aws_caller_identity(aws)["account_id"]


def resolve_iam_simulation_principal(aws: AwsCLI, identity: dict[str, str]) -> tuple[str, str]:
    arn = identity["arn"]
    partition, service, _region, account, resource = arn.split(":", 5)[1:]
    if service == "iam" and resource.startswith("user/"):
        return "user", arn
    if service == "iam" and resource.startswith("role/"):
        return "role", arn
    if service != "sts" or not resource.startswith("assumed-role/"):
        raise LifecycleError("AWS capability preflight requires an IAM user/role or STS assumed-role caller")
    assumed = resource.removeprefix("assumed-role/")
    role_name, separator, session_name = assumed.partition("/")
    if (
        not separator
        or not re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", role_name)
        or not session_name
    ):
        raise LifecycleError("AWS assumed-role caller identity has an invalid role/session shape")
    response = aws.json(["iam", "get-role", "--role-name", role_name])
    role = response.get("Role")
    role_arn = role.get("Arn") if isinstance(role, dict) else None
    if (
        not isinstance(role, dict)
        or role.get("RoleName") != role_name
        or not isinstance(role_arn, str)
        or not re.fullmatch(
            rf"arn:{re.escape(partition)}:iam::{re.escape(account)}:role/(?:[A-Za-z0-9+=,.@_-]+/)*{re.escape(role_name)}",
            role_arn,
        )
    ):
        raise LifecycleError("AWS assumed-role caller could not be resolved to one exact IAM role ARN")
    return "assumed-role", role_arn


def simulation_pass_role_arns(config: RunConfig, account_id: str) -> list[str]:
    partition = str(config.backend["kms_key_arn"]).split(":", 2)[1]
    names = [
        f"{config.run_id}-west-appliance",
        f"{config.run_id}-east-appliance",
        f"{config.run_id}-west-workload",
        f"{config.run_id}-east-workload",
        f"{config.run_id}-flow-logs",
    ]
    return [f"arn:{partition}:iam::{account_id}:role/{name}" for name in names]


def protected_common_tags(config: RunConfig) -> dict[str, str]:
    return {
        **{str(key): str(value) for key, value in config.raw["tags"].items()},
        "EnvelopeRun": config.run_id,
        "ExpiresAt": config.expires_at,
        "ManagedBy": "terraform",
        "Profile": "envelope-aws-appliance",
    }


def simulation_context_entries(
    config: RunConfig,
    *,
    region: str | None = None,
    request_tags: bool = False,
    resource_tags: bool = False,
    tag_keys: bool = False,
    ec2_create_action: str | None = None,
    elbv2_create_action: str | None = None,
    passed_to_service: str | None = None,
    kms_via_service: str | None = None,
    kms_encryption_context: tuple[str, str] | None = None,
    s3_location_constraint: str | None = None,
    extra_context: dict[str, str | tuple[str, ...]] | None = None,
) -> tuple[dict[str, Any], ...]:
    values: dict[str, tuple[str, tuple[str, ...]]] = {}
    if region is not None:
        values["aws:RequestedRegion"] = ("string", (region,))
    if request_tags or resource_tags or tag_keys:
        tags = protected_common_tags(config)
        for key, value in sorted(tags.items()):
            if request_tags:
                values[f"aws:RequestTag/{key}"] = ("string", (value,))
            if resource_tags:
                values[f"aws:ResourceTag/{key}"] = ("string", (value,))
        if request_tags or tag_keys:
            values["aws:TagKeys"] = ("stringList", tuple(sorted(tags)))
    if ec2_create_action is not None:
        values["ec2:CreateAction"] = ("string", (ec2_create_action,))
    if elbv2_create_action is not None:
        values["elasticloadbalancing:CreateAction"] = ("string", (elbv2_create_action,))
    if passed_to_service is not None:
        values["iam:PassedToService"] = ("string", (passed_to_service,))
    if kms_via_service is not None:
        values["kms:ViaService"] = ("string", (kms_via_service,))
    if kms_encryption_context is not None:
        key, value = kms_encryption_context
        values[f"kms:EncryptionContext:{key}"] = ("string", (value,))
        values["kms:EncryptionContextKeys"] = ("stringList", (key,))
    if s3_location_constraint is not None:
        values["s3:LocationConstraint"] = ("string", (s3_location_constraint,))
    for key, value in (extra_context or {}).items():
        context_values = (value,) if isinstance(value, str) else value
        if (
            not isinstance(key, str)
            or not key
            or key in values
            or not isinstance(context_values, tuple)
            or not context_values
            or not all(isinstance(item, str) and item for item in context_values)
        ):
            raise LifecycleError("AWS IAM simulation received malformed or duplicate exact context")
        values[key] = ("string" if isinstance(value, str) else "stringList", context_values)
    return tuple(
        {
            "ContextKeyName": key,
            "ContextKeyValues": list(context_values),
            "ContextKeyType": context_type,
        }
        for key, (context_type, context_values) in sorted(values.items())
    )


def build_operator_simulation_batches(
    config: RunConfig,
    account_id: str,
    artifact: dict[str, Any],
    *,
    policy_source_arn: str,
) -> list[dict[str, Any]]:
    revision = artifact.get("revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise LifecycleError("AWS IAM simulation requires the exact reviewed artifact revision")
    if (
        not isinstance(policy_source_arn, str)
        or not re.fullmatch(
            rf"arn:aws:iam::{re.escape(account_id)}:(?:role|user)/"
            r"(?:[A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]{1,64}",
            policy_source_arn,
        )
    ):
        raise LifecycleError("AWS IAM simulation requires the exact resolved commercial policy source ARN")
    partition = str(config.backend["kms_key_arn"]).split(":", 2)[1]
    dns_suffix = AWS_PARTITION_DNS_SUFFIXES[partition]
    artifact_bucket = f"{config.run_id}-{account_id}-{config.sites['west']['region']}-artifact"
    artifact_bucket_arn = f"arn:{partition}:s3:::{artifact_bucket}"
    artifact_object_arn = f"{artifact_bucket_arn}/artifacts/{revision}/envelope-linux-{config.architecture}"
    backend_bucket_arn = f"arn:{partition}:s3:::{config.backend['bucket']}"
    backend_object_arns = tuple(
        f"{backend_bucket_arn}/{key}"
        for key in (config.backend["state_key"], config.lock_key, config.manifest_key)
    )
    roles = tuple(simulation_pass_role_arns(config, account_id))
    profiles = tuple(
        f"arn:{partition}:iam::{account_id}:instance-profile/{config.run_id}-{site}-{role}"
        for site in ("west", "east")
        for role in ("appliance", "workload")
    )
    parameters = {
        value["site"]: str(value["arn"])
        for value in intended_ssm_parameters(config, account_id)
    }
    log_groups = {
        site: f"arn:{partition}:logs:{config.sites[site]['region']}:{account_id}:log-group:/aws/vpc-flow-logs/{config.run_id}/{site}"
        for site in ("west", "east")
    }
    batches: list[dict[str, Any]] = []

    def add(
        name: str,
        actions: Iterable[str],
        resources: Iterable[str],
        context: tuple[dict[str, Any], ...] = (),
    ) -> None:
        action_values = tuple(sorted(set(actions)))
        resource_values = tuple(sorted(set(resources)))
        if not action_values or not resource_values:
            raise LifecycleError(f"AWS IAM simulation batch {name} is empty")
        if any(action not in AWS_OPERATOR_ACTIONS for action in action_values):
            raise LifecycleError(f"AWS IAM simulation batch {name} contains an unknown action")
        batches.append(
            {
                "name": name,
                "actions": action_values,
                "resources": resource_values,
                "context": context,
            }
        )

    def add_contract_groups(
        prefix: str,
        contract: dict[str, tuple[str, ...]],
        resources_by_kind: dict[str, tuple[str, ...]],
        *,
        resource_contexts_by_action: dict[
            str,
            tuple[
                tuple[tuple[str, ...], tuple[dict[str, Any], ...]],
                ...,
            ],
        ],
    ) -> None:
        if set(resource_contexts_by_action) != set(contract):
            raise LifecycleError(f"AWS IAM context contract {prefix} does not cover its exact actions")
        grouped: dict[tuple[tuple[str, ...], str], set[str]] = {}
        context_values: dict[str, tuple[dict[str, Any], ...]] = {}
        for action, required_resource_kinds in contract.items():
            resource_contexts = resource_contexts_by_action[action]
            planned_resource_kinds = tuple(
                resource_kind
                for resource_kinds, _context in resource_contexts
                for resource_kind in resource_kinds
            )
            if (
                not resource_contexts
                or len(planned_resource_kinds) != len(set(planned_resource_kinds))
                or set(planned_resource_kinds) != set(required_resource_kinds)
            ):
                raise LifecycleError(
                    f"AWS IAM context contract {prefix} does not cover exact resources for {action}"
                )
            for resource_kinds, context in resource_contexts:
                if not resource_kinds:
                    raise LifecycleError(f"AWS IAM context contract {prefix} has an empty resource path")
                serialized_context = json.dumps(context, sort_keys=True, separators=(",", ":"))
                context_values[serialized_context] = context
                grouped.setdefault((resource_kinds, serialized_context), set()).add(action)
        for index, ((resource_kinds, serialized_context), actions) in enumerate(
            sorted(grouped.items()),
            start=1,
        ):
            try:
                resources = tuple(
                    resource
                    for resource_kind in resource_kinds
                    for resource in resources_by_kind[resource_kind]
                )
            except KeyError as error:
                raise LifecycleError(
                    f"AWS IAM action/resource contract {prefix} references unknown kind {error.args[0]}"
                ) from error
            label = "-".join(resource_kinds[:2]).replace("*", "global")
            add(
                f"{prefix}-{index:02d}-{label}",
                actions,
                resources,
                context_values[serialized_context],
            )

    actions_by_service = {
        service: {action for action in AWS_OPERATOR_ACTIONS if action.startswith(f"{service}:")}
        for service in {action.split(":", 1)[0] for action in AWS_OPERATOR_ACTIONS}
    }
    for site in ("west", "east"):
        region = str(config.sites[site]["region"])
        regional_context = simulation_context_entries(config, region=region)
        request_tag_context = simulation_context_entries(
            config,
            region=region,
            request_tags=True,
        )
        resource_tag_context = simulation_context_entries(
            config,
            region=region,
            resource_tags=True,
        )
        remove_tag_context = simulation_context_entries(
            config,
            region=region,
            resource_tags=True,
            tag_keys=True,
        )
        ec2_resources = {
            "*": ("*",),
            "image": (f"arn:{partition}:ec2:{region}::image/{config.sites[site]['ami_id']}",),
            **{
                kind: (f"arn:{partition}:ec2:{region}:{account_id}:{kind}/*",)
                for kind in {
                    "elastic-ip",
                    "instance",
                    "internet-gateway",
                    "natgateway",
                    "network-acl",
                    "network-interface",
                    "route-table",
                    "security-group",
                    "subnet",
                    "volume",
                    "vpc",
                    "vpc-endpoint",
                    "vpc-endpoint-service",
                    "vpc-flow-log",
                }
            },
        }
        ec2_tagged_create_actions = {
            "ec2:AllocateAddress",
            "ec2:CreateFlowLogs",
            "ec2:CreateInternetGateway",
            "ec2:CreateNatGateway",
            "ec2:CreateNetworkAcl",
            "ec2:CreateNetworkInterface",
            "ec2:CreateRouteTable",
            "ec2:CreateSecurityGroup",
            "ec2:CreateSubnet",
            "ec2:CreateVolume",
            "ec2:CreateVpc",
            "ec2:CreateVpcEndpoint",
            "ec2:CreateVpcEndpointServiceConfiguration",
            "ec2:RunInstances",
        }
        ec2_untagged_create_actions = {
            "ec2:CreateNetworkAclEntry",
            "ec2:CreateRoute",
        }
        ec2_tag_actions = {"ec2:CreateTags", "ec2:DeleteTags"}
        ec2_core_contract = {
            action: resource_kinds
            for action, resource_kinds in AWS_EC2_ACTION_RESOURCE_CONTRACT.items()
            if action not in ec2_tag_actions and action != AWS_RUN_INSTANCES_DRY_RUN_ACTION
        }
        ec2_mixed_create_contexts = {
            "ec2:CreateFlowLogs": (
                (("vpc-flow-log",), request_tag_context),
                (("vpc",), resource_tag_context),
            ),
            "ec2:CreateNatGateway": (
                (("natgateway",), request_tag_context),
                (("subnet", "elastic-ip"), resource_tag_context),
            ),
            "ec2:CreateNetworkAcl": (
                (("network-acl",), request_tag_context),
                (("vpc",), resource_tag_context),
            ),
            "ec2:CreateNetworkInterface": (
                (("network-interface",), request_tag_context),
                (("subnet", "security-group"), resource_tag_context),
            ),
            "ec2:CreateRouteTable": (
                (("route-table",), request_tag_context),
                (("vpc",), resource_tag_context),
            ),
            "ec2:CreateSecurityGroup": (
                (("security-group",), request_tag_context),
                (("vpc",), resource_tag_context),
            ),
            "ec2:CreateSubnet": (
                (("subnet",), request_tag_context),
                (("vpc",), resource_tag_context),
            ),
            "ec2:CreateVpcEndpoint": (
                (("vpc-endpoint",), request_tag_context),
                (("vpc", "subnet"), resource_tag_context),
            ),
        }
        ec2_resource_contexts: dict[
            str,
            tuple[
                tuple[tuple[str, ...], tuple[dict[str, Any], ...]],
                ...,
            ],
        ] = {}
        for action, resource_kinds in ec2_core_contract.items():
            if action in ec2_mixed_create_contexts:
                ec2_resource_contexts[action] = ec2_mixed_create_contexts[action]
            elif resource_kinds == ("*",) or action in ec2_untagged_create_actions:
                ec2_resource_contexts[action] = ((resource_kinds, regional_context),)
            elif action in ec2_tagged_create_actions:
                ec2_resource_contexts[action] = ((resource_kinds, request_tag_context),)
            else:
                ec2_resource_contexts[action] = ((resource_kinds, resource_tag_context),)
        add_contract_groups(
            f"ec2-{site}",
            ec2_core_contract,
            ec2_resources,
            resource_contexts_by_action=ec2_resource_contexts,
        )
        ec2_create_tag_paths = {
            "AllocateAddress": ("elastic-ip",),
            "CreateFlowLogs": ("vpc-flow-log",),
            "CreateInternetGateway": ("internet-gateway",),
            "CreateNatGateway": ("natgateway",),
            "CreateNetworkAcl": ("network-acl",),
            "CreateNetworkInterface": ("network-interface",),
            "CreateRouteTable": ("route-table",),
            "CreateSecurityGroup": ("security-group",),
            "CreateSubnet": ("subnet",),
            "CreateVolume": ("volume",),
            "CreateVpc": ("vpc",),
            "CreateVpcEndpoint": ("vpc-endpoint",),
            "CreateVpcEndpointServiceConfiguration": ("vpc-endpoint-service",),
            "RunInstances": ("instance", "volume"),
        }
        if ec2_tagged_create_actions != {
            f"ec2:{create_action}" for create_action in ec2_create_tag_paths
        }:
            raise LifecycleError("AWS EC2 tag-on-create paths differ from the creation context contract")
        for create_action, resource_kinds in ec2_create_tag_paths.items():
            add(
                f"ec2-{site}-create-tags-{create_action}",
                {"ec2:CreateTags"},
                tuple(
                    resource
                    for resource_kind in resource_kinds
                    for resource in ec2_resources[resource_kind]
                ),
                simulation_context_entries(
                    config,
                    region=region,
                    request_tags=True,
                    ec2_create_action=create_action,
                ),
            )
        add(
            f"ec2-{site}-tag-existing",
            {"ec2:CreateTags"},
            tuple(
                resource
                for resource_kind in AWS_EC2_ACTION_RESOURCE_CONTRACT["ec2:CreateTags"]
                for resource in ec2_resources[resource_kind]
            ),
            simulation_context_entries(
                config,
                region=region,
                request_tags=True,
                resource_tags=True,
            ),
        )
        add(
            f"ec2-{site}-delete-tags",
            {"ec2:DeleteTags"},
            tuple(
                resource
                for resource_kind in AWS_EC2_ACTION_RESOURCE_CONTRACT["ec2:DeleteTags"]
                for resource in ec2_resources[resource_kind]
            ),
            remove_tag_context,
        )

        elb_resources = {
            "*": ("*",),
            "load-balancer": (
                f"arn:{partition}:elasticloadbalancing:{region}:{account_id}:"
                f"loadbalancer/gwy/{config.run_id}-{site}-gwlb/*",
            ),
            "listener": (
                f"arn:{partition}:elasticloadbalancing:{region}:{account_id}:"
                f"listener/gwy/{config.run_id}-{site}-gwlb/*/*",
            ),
            "target-group": (
                f"arn:{partition}:elasticloadbalancing:{region}:{account_id}:"
                f"targetgroup/{config.run_id}-{site}-gwlb-tg/*",
            ),
        }
        elb_tag_actions = {"elasticloadbalancing:AddTags"}
        elb_core_contract = {
            action: resource_kinds
            for action, resource_kinds in AWS_ELBV2_ACTION_RESOURCE_CONTRACT.items()
            if action not in elb_tag_actions
        }
        elb_tagged_create_actions = {
            "elasticloadbalancing:CreateListener",
            "elasticloadbalancing:CreateLoadBalancer",
            "elasticloadbalancing:CreateTargetGroup",
        }
        elb_create_tag_paths = {
            "CreateListener": "*",
            "CreateLoadBalancer": "*",
            "CreateTargetGroup": "*",
        }
        if elb_tagged_create_actions != {
            f"elasticloadbalancing:{create_action}"
            for create_action in elb_create_tag_paths
        }:
            raise LifecycleError("AWS ELB tag-on-create paths differ from the creation context contract")
        elb_resource_contexts = {}
        for action, resource_kinds in elb_core_contract.items():
            if action == "elasticloadbalancing:CreateListener":
                elb_resource_contexts[action] = (
                    (
                        ("load-balancer",),
                        simulation_context_entries(
                            config,
                            region=region,
                            request_tags=True,
                            resource_tags=True,
                        ),
                    ),
                )
                continue
            context = (
                regional_context
                if resource_kinds == ("*",)
                else request_tag_context
                if action in elb_tagged_create_actions
                else resource_tag_context
            )
            elb_resource_contexts[action] = ((resource_kinds, context),)
        add_contract_groups(
            f"elbv2-{site}",
            elb_core_contract,
            elb_resources,
            resource_contexts_by_action=elb_resource_contexts,
        )
        for create_action, resource_kind in elb_create_tag_paths.items():
            add(
                f"elbv2-{site}-add-tags-{create_action}",
                {"elasticloadbalancing:AddTags"},
                elb_resources[resource_kind],
                simulation_context_entries(
                    config,
                    region=region,
                    request_tags=True,
                    elbv2_create_action=create_action,
                ),
            )

        logs_actions = actions_by_service["logs"]
        add(
            f"logs-{site}-discovery",
            {"logs:DescribeLogGroups"},
            ("*",),
            regional_context,
        )
        add(
            f"logs-{site}-create",
            {"logs:CreateLogGroup"},
            (log_groups[site],),
            request_tag_context,
        )
        add(
            f"logs-{site}-group",
            logs_actions
            - {
                "logs:CreateLogGroup",
                "logs:DescribeLogGroups",
                "logs:TagResource",
                "logs:UntagResource",
            },
            (log_groups[site],),
            resource_tag_context,
        )
        add(
            f"logs-{site}-tag",
            {"logs:TagResource"},
            (log_groups[site],),
            simulation_context_entries(
                config,
                region=region,
                request_tags=True,
                resource_tags=True,
            ),
        )
        add(
            f"logs-{site}-untag",
            {"logs:UntagResource"},
            (log_groups[site],),
            remove_tag_context,
        )

        add(
            f"ssm-{site}-parameter-create",
            {"ssm:PutParameter"},
            (parameters[site],),
            request_tag_context,
        )
        add(
            f"ssm-{site}-parameter-update",
            {"ssm:PutParameter"},
            (parameters[site],),
            resource_tag_context,
        )
        parameter_existing_actions = {
            "ssm:DeleteParameter",
            "ssm:GetParameter",
            "ssm:ListTagsForResource",
        }
        add(
            f"ssm-{site}-parameter",
            parameter_existing_actions,
            (parameters[site],),
            resource_tag_context,
        )
        add(
            f"ssm-{site}-parameter-tag",
            {"ssm:AddTagsToResource"},
            (parameters[site],),
            simulation_context_entries(
                config,
                region=region,
                request_tags=True,
                resource_tags=True,
            ),
        )
        add(
            f"ssm-{site}-parameter-untag",
            {"ssm:RemoveTagsFromResource"},
            (parameters[site],),
            remove_tag_context,
        )
        add(
            f"ssm-{site}-command-control",
            {
                "ssm:CancelCommand",
                "ssm:DescribeInstanceInformation",
                "ssm:DescribeParameters",
                "ssm:GetCommandInvocation",
            },
            ("*",),
            simulation_context_entries(config, region=region),
        )
        add(
            f"ssm-{site}-send-command",
            {"ssm:SendCommand"},
            (
                f"arn:{partition}:ec2:{region}:{account_id}:instance/*",
                f"arn:{partition}:ssm:{region}::document/AWS-RunShellScript",
            ),
            regional_context,
        )
        for gate, (service_code, quota_code, _name) in AWS_REGIONAL_QUOTA_CONTRACT.items():
            add(
                f"service-quota-{site}-{gate}",
                actions_by_service["servicequotas"],
                (
                    f"arn:{partition}:servicequotas:{region}:{account_id}:"
                    f"{service_code}/{quota_code}",
                ),
                simulation_context_entries(
                    config,
                    region=region,
                    extra_context={"servicequotas:service": service_code},
                ),
            )
        add(
            f"tagging-{site}",
            actions_by_service["tag"],
            ("*",),
            regional_context,
        )

    global_control_region = AWS_GLOBAL_QUOTA_CONTROL_REGIONS[partition]
    for gate, (service_code, quota_code, _name) in AWS_GLOBAL_QUOTA_CONTRACT.items():
        add(
            f"service-quota-global-{gate}",
            actions_by_service["servicequotas"],
            (
                f"arn:{partition}:servicequotas:{global_control_region}:{account_id}:"
                f"{service_code}/{quota_code}",
            ),
            simulation_context_entries(
                config,
                region=global_control_region,
                extra_context={"servicequotas:service": service_code},
            ),
        )

    iam_actions = actions_by_service["iam"]
    iam_global_actions = {
        action
        for action, resource_kinds in AWS_IAM_ACTION_RESOURCE_CONTRACT.items()
        if resource_kinds == ("*",)
    }
    iam_role_actions = {
        action
        for action, resource_kinds in AWS_IAM_ACTION_RESOURCE_CONTRACT.items()
        if resource_kinds == ("role",)
    }
    iam_profile_actions = {
        action
        for action, resource_kinds in AWS_IAM_ACTION_RESOURCE_CONTRACT.items()
        if resource_kinds == ("instance-profile",)
    }
    add("iam-global", iam_global_actions, ("*",))
    add("iam-policy-source", {"iam:SimulatePrincipalPolicy"}, (policy_source_arn,))
    add(
        "iam-role-create",
        {"iam:CreateRole"},
        roles,
        simulation_context_entries(config, request_tags=True),
    )
    add(
        "iam-roles",
        iam_role_actions - {"iam:CreateRole", "iam:TagRole", "iam:UntagRole"},
        roles,
        simulation_context_entries(config, resource_tags=True),
    )
    add(
        "iam-role-tag",
        {"iam:TagRole"},
        roles,
        simulation_context_entries(config, request_tags=True, resource_tags=True),
    )
    add(
        "iam-role-untag",
        {"iam:UntagRole"},
        roles,
        simulation_context_entries(config, resource_tags=True, tag_keys=True),
    )
    add(
        "iam-instance-profile-create",
        {"iam:CreateInstanceProfile"},
        profiles,
        simulation_context_entries(config, request_tags=True),
    )
    add(
        "iam-instance-profiles",
        iam_profile_actions
        - {"iam:CreateInstanceProfile", "iam:TagInstanceProfile", "iam:UntagInstanceProfile"},
        profiles,
        simulation_context_entries(config, resource_tags=True),
    )
    add(
        "iam-instance-profile-tag",
        {"iam:TagInstanceProfile"},
        profiles,
        simulation_context_entries(config, request_tags=True, resource_tags=True),
    )
    add(
        "iam-instance-profile-untag",
        {"iam:UntagInstanceProfile"},
        profiles,
        simulation_context_entries(config, resource_tags=True, tag_keys=True),
    )
    add(
        "iam-passrole-ec2",
        {"iam:PassRole"},
        roles[:4],
        simulation_context_entries(
            config,
            passed_to_service=f"ec2.{dns_suffix}",
        ),
    )
    add(
        "iam-passrole-flow-logs",
        {"iam:PassRole"},
        (roles[4],),
        simulation_context_entries(
            config,
            passed_to_service=f"vpc-flow-logs.{dns_suffix}",
        ),
    )
    if iam_actions != set(AWS_IAM_ACTION_RESOURCE_CONTRACT):
        raise LifecycleError("AWS IAM simulation contract differs from the exact IAM operator actions")

    kms_metadata_actions = {"kms:DescribeKey", "kms:GetKeyPolicy"}
    kms_crypto_actions = {"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"}
    backend_region = str(config.backend["region"])
    add(
        "kms-backend-metadata",
        kms_metadata_actions,
        (str(config.backend["kms_key_arn"]),),
        simulation_context_entries(config, region=backend_region),
    )
    for label in ("state", "lock", "manifest"):
        add(
            f"kms-backend-s3-{label}",
            kms_crypto_actions,
            (str(config.backend["kms_key_arn"]),),
            simulation_context_entries(
                config,
                region=backend_region,
                kms_via_service=f"s3.{backend_region}.{dns_suffix}",
                kms_encryption_context=("aws:s3:arn", backend_bucket_arn),
            ),
        )
    for site in ("west", "east"):
        region = str(config.sites[site]["region"])
        key_arn = str(config.sites[site]["ssm_kms_key_arn"])
        add(
            f"kms-{site}-metadata",
            kms_metadata_actions,
            (key_arn,),
            simulation_context_entries(config, region=region),
        )
        add(
            f"kms-{site}-ssm",
            kms_crypto_actions,
            (key_arn,),
            simulation_context_entries(
                config,
                region=region,
                kms_via_service=f"ssm.{region}.{dns_suffix}",
                kms_encryption_context=("PARAMETER_ARN", parameters[site]),
            ),
        )

    s3_actions = actions_by_service["s3"]
    s3_global_actions = {"s3:ListAllMyBuckets"}
    s3_object_actions = {
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:GetObject",
        "s3:GetObjectAttributes",
        "s3:GetObjectTagging",
        "s3:PutObject",
        "s3:PutObjectTagging",
    }
    s3_bucket_actions = s3_actions - s3_global_actions - s3_object_actions
    artifact_region = str(config.sites["west"]["region"])
    artifact_resource_context = simulation_context_entries(
        config,
        region=artifact_region,
        resource_tags=True,
    )
    artifact_object_tags = {
        "s3:RequestObjectTag/EnvelopeRun": config.run_id,
        "s3:RequestObjectTag/ExpiresAt": config.expires_at,
    }
    add(
        "s3-global",
        s3_global_actions,
        ("*",),
        simulation_context_entries(config, region=global_control_region),
    )
    add(
        "s3-artifact-create",
        {"s3:CreateBucket"},
        (artifact_bucket_arn,),
        simulation_context_entries(
            config,
            region=artifact_region,
            s3_location_constraint=artifact_region,
        ),
    )
    add(
        "s3-artifact-bucket",
        s3_bucket_actions - {"s3:CreateBucket", "s3:PutBucketTagging"},
        (artifact_bucket_arn,),
        artifact_resource_context,
    )
    add(
        "s3-artifact-bucket-tag",
        {"s3:PutBucketTagging"},
        (artifact_bucket_arn,),
        simulation_context_entries(
            config,
            region=artifact_region,
            request_tags=True,
            resource_tags=True,
        ),
    )
    add(
        "s3-artifact-object",
        s3_object_actions - {"s3:PutObject", "s3:PutObjectTagging"},
        (artifact_object_arn,),
        artifact_resource_context,
    )
    add(
        "s3-artifact-object-put",
        {"s3:PutObject"},
        (artifact_object_arn,),
        simulation_context_entries(
            config,
            region=artifact_region,
            extra_context=artifact_object_tags,
        ),
    )
    add(
        "s3-artifact-object-put-tags",
        {"s3:PutObjectTagging"},
        (artifact_object_arn,),
        simulation_context_entries(
            config,
            region=artifact_region,
            resource_tags=True,
            extra_context=artifact_object_tags,
        ),
    )
    backend_list_actions = {"s3:ListBucket", "s3:ListBucketVersions"}
    add(
        "s3-backend-bucket-metadata",
        set(BACKEND_BUCKET_ACTIONS).intersection(s3_actions) - backend_list_actions,
        (backend_bucket_arn,),
        simulation_context_entries(config, region=backend_region),
    )
    backend_keys = {
        "state": str(config.backend["state_key"]),
        "lock": config.lock_key,
        "manifest": config.manifest_key,
    }
    for label, key in backend_keys.items():
        add(
            f"s3-backend-list-{label}",
            backend_list_actions,
            (backend_bucket_arn,),
            simulation_context_entries(
                config,
                region=backend_region,
                extra_context={"s3:prefix": key},
            ),
        )

    ownership_context = {
        "s3:RequestObjectTag/EnvelopeRun": config.run_id,
        "s3:RequestObjectTag/ExpiresAt": config.expires_at,
    }
    put_context = {
        "s3:x-amz-server-side-encryption": "aws:kms",
        "s3:x-amz-server-side-encryption-aws-kms-key-id": str(config.backend["kms_key_arn"]),
    }
    object_by_label = dict(zip(("state", "lock", "manifest"), backend_object_arns, strict=True))
    for label, object_arn in object_by_label.items():
        read_actions = {"s3:GetObject", "s3:DeleteObjectVersion"}
        if label == "lock":
            read_actions.add("s3:DeleteObject")
        if label == "manifest":
            add(
                "s3-backend-manifest-get",
                {"s3:GetObject"},
                (object_arn,),
                simulation_context_entries(
                    config,
                    region=backend_region,
                    extra_context={
                        "s3:ExistingObjectTag/EnvelopeRun": config.run_id,
                        "s3:ExistingObjectTag/ExpiresAt": config.expires_at,
                    },
                ),
            )
            read_actions.remove("s3:GetObject")
        add(
            f"s3-backend-{label}-read-delete",
            read_actions,
            (object_arn,),
            simulation_context_entries(config, region=backend_region),
        )
        add(
            f"s3-backend-{label}-put",
            {"s3:PutObject"},
            (object_arn,),
            simulation_context_entries(
                config,
                region=backend_region,
                extra_context={**put_context, **(ownership_context if label == "manifest" else {})},
            ),
        )
    add(
        "s3-backend-manifest-put-tags",
        {"s3:PutObjectTagging"},
        (object_by_label["manifest"],),
        simulation_context_entries(
            config,
            region=backend_region,
            extra_context=ownership_context,
        ),
    )

    covered = {action for batch in batches for action in batch["actions"]}
    if covered != set(AWS_IAM_SIMULATED_OPERATOR_ACTIONS):
        raise LifecycleError(
            "AWS IAM simulation batches do not cover the exact simulated action contract: "
            f"{sorted(set(AWS_IAM_SIMULATED_OPERATOR_ACTIONS) - covered)}"
        )
    return sorted(batches, key=lambda value: str(value["name"]))


def simulate_operator_actions(
    aws: AwsCLI,
    policy_source_arn: str,
    config: RunConfig,
    account_id: str,
    artifact: dict[str, Any],
) -> None:
    valid_decisions = {"allowed", "implicitDeny", "explicitDeny"}
    for batch in build_operator_simulation_batches(
        config,
        account_id,
        artifact,
        policy_source_arn=policy_source_arn,
    ):
        actions = list(batch["actions"])
        resources = list(batch["resources"])
        context = list(batch["context"])
        for offset in range(0, len(actions), IAM_SIMULATION_ACTION_CHUNK_SIZE):
            requested = actions[offset : offset + IAM_SIMULATION_ACTION_CHUNK_SIZE]
            args = [
                "iam",
                "simulate-principal-policy",
                "--policy-source-arn",
                policy_source_arn,
                "--action-names",
                *requested,
                "--resource-arns",
                *resources,
            ]
            if context:
                args.extend(["--context-entries", json.dumps(context, sort_keys=True, separators=(",", ":"))])
            response = aws.json(args)
            results = response.get("EvaluationResults")
            if not isinstance(results, list) or not all(isinstance(value, dict) for value in results):
                raise LifecycleError("AWS IAM capability simulation returned a malformed result schema")
            if response.get("IsTruncated") not in (None, False):
                raise LifecycleError("AWS IAM capability simulation returned an incomplete result set")
            by_action: dict[str, dict[str, Any]] = {}
            for result in results:
                action = result.get("EvalActionName")
                if not isinstance(action, str) or action in by_action:
                    raise LifecycleError("AWS IAM capability simulation returned a duplicate or invalid action")
                by_action[action] = result
            if set(by_action) != set(requested):
                missing = sorted(set(requested) - set(by_action))
                raise LifecycleError(f"AWS IAM capability simulation omitted required action(s): {missing}")
            for action in requested:
                result = by_action[action]
                decision = result.get("EvalDecision")
                if decision not in valid_decisions:
                    raise LifecycleError(f"AWS IAM capability simulation returned an invalid decision for {action}")
                denied_by_guardrail = False
                resource_results = result.get("ResourceSpecificResults")
                if resource_results is not None:
                    if not isinstance(resource_results, list) or not all(isinstance(value, dict) for value in resource_results):
                        raise LifecycleError(f"AWS IAM capability simulation returned malformed resources for {action}")
                    decisions_by_resource: dict[str, str] = {}
                    for resource_result in resource_results:
                        resource_name = resource_result.get("EvalResourceName")
                        resource_decision = resource_result.get("EvalResourceDecision")
                        if (
                            not isinstance(resource_name, str)
                            or resource_name not in resources
                            or resource_name in decisions_by_resource
                            or resource_decision not in valid_decisions
                        ):
                            raise LifecycleError(f"AWS IAM capability simulation returned a conflicting resource for {action}")
                        decisions_by_resource[resource_name] = str(resource_decision)
                    if set(decisions_by_resource) != set(resources):
                        missing = sorted(set(resources) - set(decisions_by_resource))
                        raise LifecycleError(
                            f"AWS IAM capability simulation omitted mandatory resource(s) for {action} "
                            f"in batch {batch['name']}: {missing}"
                        )
                elif len(resources) > 1:
                    raise LifecycleError(
                        f"AWS IAM capability simulation omitted mandatory resource decisions for {action} "
                        f"in batch {batch['name']}"
                    )
                else:
                    decisions_by_resource = {resources[0]: str(decision)}
                for field, decision_field in (
                    ("PermissionsBoundaryDecisionDetail", "AllowedByPermissionsBoundary"),
                    ("OrganizationsDecisionDetail", "AllowedByOrganizations"),
                ):
                    detail = result.get(field)
                    if detail is not None and (
                        not isinstance(detail, dict) or not isinstance(detail.get(decision_field), bool)
                    ):
                        raise LifecycleError(f"AWS IAM capability simulation returned malformed {field} for {action}")
                    if isinstance(detail, dict) and detail[decision_field] is False:
                        denied_by_guardrail = True
                if decision == "explicitDeny" or denied_by_guardrail or "explicitDeny" in decisions_by_resource.values():
                    raise LifecycleError(
                        f"AWS IAM capability preflight explicitly denied {action} in simulation batch {batch['name']}"
                    )
                missing_context = result.get("MissingContextValues", [])
                if not isinstance(missing_context, list) or not all(isinstance(value, str) and value for value in missing_context):
                    raise LifecycleError(f"AWS IAM capability simulation returned malformed missing context for {action}")
                if missing_context:
                    raise LifecycleError(
                        f"AWS IAM capability preflight for {action} in batch {batch['name']} has unresolved required context: "
                        + ", ".join(sorted(set(missing_context)))
                    )
                denied_resources = sorted(
                    resource for resource, resource_decision in decisions_by_resource.items() if resource_decision != "allowed"
                )
                if decision == "allowed" and not denied_resources:
                    continue
                raise LifecycleError(
                    f"AWS IAM capability preflight implicitly denied {action} on mandatory resource(s) "
                    f"in batch {batch['name']}: {denied_resources or resources}"
                )


def response_object_list(response: dict[str, Any], field: str, gate: str) -> list[dict[str, Any]]:
    values = response.get(field)
    if not isinstance(values, list) or not all(isinstance(value, dict) for value in values):
        raise LifecycleError(f"AWS preflight gate {gate} returned a malformed {field} schema")
    return values


def run_instances_dry_run_preflight(config: RunConfig, aws: AwsCLI) -> dict[str, dict[str, str]]:
    def exact_default_resource(
        site: str,
        name: str,
        args: list[str],
        field: str,
    ) -> dict[str, Any]:
        gate = f"AWS RunInstances dry-run gate {site}/{name}"
        try:
            response = aws.json(args, region=str(config.sites[site]["region"]))
        except Exception:
            raise LifecycleError(f"{gate} could not read an exact default resource") from None
        if not isinstance(response, dict) or "NextToken" in response:
            raise LifecycleError(f"{gate} returned malformed or incomplete default resource metadata")
        values = response.get(field)
        if (
            not isinstance(values, list)
            or len(values) != 1
            or not isinstance(values[0], dict)
        ):
            raise LifecycleError(f"{gate} requires exactly one matching default resource")
        return values[0]

    common_tags = [
        {"Key": key, "Value": value}
        for key, value in sorted(protected_common_tags(config).items())
    ]
    tag_specifications = json.dumps(
        [
            {"ResourceType": "instance", "Tags": common_tags},
            {"ResourceType": "volume", "Tags": common_tags},
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    summary: dict[str, dict[str, str]] = {}
    for site in ("west", "east"):
        region = str(config.sites[site]["region"])
        zone = str(next(iter(config.sites[site]["azs"].values())))
        vpc = exact_default_resource(
            site,
            "default-vpc",
            ["ec2", "describe-vpcs", "--filters", "Name=is-default,Values=true"],
            "Vpcs",
        )
        vpc_id = vpc.get("VpcId")
        if (
            not isinstance(vpc_id, str)
            or not re.fullmatch(r"vpc-[0-9a-f]{8,17}", vpc_id)
            or vpc.get("IsDefault") is not True
        ):
            raise LifecycleError(
                f"AWS RunInstances dry-run gate {site}/default-vpc returned a malformed identity"
            )
        subnet = exact_default_resource(
            site,
            "default-subnet",
            [
                "ec2",
                "describe-subnets",
                "--filters",
                f"Name=vpc-id,Values={vpc_id}",
                f"Name=availability-zone,Values={zone}",
                "Name=default-for-az,Values=true",
            ],
            "Subnets",
        )
        subnet_id = subnet.get("SubnetId")
        if (
            not isinstance(subnet_id, str)
            or not re.fullmatch(r"subnet-[0-9a-f]{8,17}", subnet_id)
            or subnet.get("VpcId") != vpc_id
            or subnet.get("AvailabilityZone") != zone
            or subnet.get("DefaultForAz") is not True
        ):
            raise LifecycleError(
                f"AWS RunInstances dry-run gate {site}/default-subnet returned a malformed identity"
            )
        security_group = exact_default_resource(
            site,
            "default-security-group",
            [
                "ec2",
                "describe-security-groups",
                "--filters",
                f"Name=vpc-id,Values={vpc_id}",
                "Name=group-name,Values=default",
            ],
            "SecurityGroups",
        )
        security_group_id = security_group.get("GroupId")
        if (
            not isinstance(security_group_id, str)
            or not re.fullmatch(r"sg-[0-9a-f]{8,17}", security_group_id)
            or security_group.get("VpcId") != vpc_id
            or security_group.get("GroupName") != "default"
        ):
            raise LifecycleError(
                f"AWS RunInstances dry-run gate {site}/default-security-group returned a malformed identity"
            )

        summary[site] = {}
        for instance_class, instance_type in (
            ("target", str(config.raw["instance_type"])),
            ("ingress_router", str(config.raw["instance_type"])),
            ("workload", str(config.raw["test_instance_type"])),
        ):
            gate = f"AWS RunInstances dry-run gate {site}/{instance_class}"
            args = [
                "ec2",
                "run-instances",
                "--dry-run",
                "--image-id",
                str(config.sites[site]["ami_id"]),
                "--instance-type",
                instance_type,
                "--count",
                "1",
                "--subnet-id",
                subnet_id,
                "--security-group-ids",
                security_group_id,
                "--metadata-options",
                "HttpTokens=required,HttpEndpoint=enabled",
                "--tag-specifications",
                tag_specifications,
            ]
            try:
                aws.json(args, region=region)
            except CommandError as error:
                if (
                    type(error.returncode) is int
                    and error.returncode != 0
                    and isinstance(error.raw_stderr, str)
                    and error.raw_stderr.strip() == AWS_RUN_INSTANCES_DRY_RUN_SUCCESS
                ):
                    summary[site][instance_class] = instance_type
                    continue
                raise LifecycleError(f"{gate} did not return exact DryRunOperation success") from None
            except Exception:
                raise LifecycleError(f"{gate} failed before exact DryRunOperation success") from None
            raise LifecycleError(f"{gate} returned normally instead of exact DryRunOperation success")
    return summary


def normalized_capacity_number(value: float) -> int | float:
    return int(value) if value.is_integer() else value


def service_quota_values(
    aws: AwsCLI,
    region: str,
    contract: dict[str, tuple[str, str, str]],
    identity_arn: str,
    *,
    global_quotas: bool,
) -> dict[str, dict[str, Any]]:
    identity_parts = identity_arn.split(":", 5)
    if (
        len(identity_parts) != 6
        or identity_parts[0] != "arn"
        or identity_parts[1] not in AWS_GLOBAL_QUOTA_CONTROL_REGIONS
        or not re.fullmatch(r"[0-9]{12}", identity_parts[4])
    ):
        raise LifecycleError("AWS quota preflight received a malformed caller identity ARN")
    partition, account_id = identity_parts[1], identity_parts[4]
    by_gate: dict[str, dict[str, Any]] = {}
    for gate, (service, quota_code, documented_name) in sorted(contract.items()):
        try:
            response = aws.json(
                [
                    "service-quotas",
                    "get-service-quota",
                    "--service-code",
                    service,
                    "--quota-code",
                    quota_code,
                ],
                region=region,
            )
        except CommandError as error:
            raise LifecycleError(
                f"AWS quota preflight gate {gate} could not read stable quota {quota_code} "
                f"({documented_name}) in {region}"
            ) from error
        quota = response.get("Quota") if isinstance(response, dict) else None
        name = quota.get("QuotaName") if isinstance(quota, dict) else None
        value = quota.get("Value") if isinstance(quota, dict) else None
        quota_arn_region = "" if global_quotas else region
        expected_quota_arn = (
            f"arn:{partition}:servicequotas:{quota_arn_region}:{account_id}:{service}/{quota_code}"
        )
        if (
            not isinstance(quota, dict)
            or quota.get("ServiceCode") != service
            or quota.get("QuotaCode") != quota_code
            or quota.get("QuotaArn") != expected_quota_arn
            or not isinstance(name, str)
            or not name
            or isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) < 0
            or quota.get("GlobalQuota") is not global_quotas
        ):
            raise LifecycleError(
                f"AWS quota preflight gate {gate} returned mismatched or malformed quota "
                f"{quota_code} ({documented_name}) in {region}"
            )
        by_gate[gate] = quota
    return by_gate


def regional_service_quota_values(
    aws: AwsCLI,
    region: str,
    identity_arn: str,
) -> dict[str, dict[str, Any]]:
    return service_quota_values(
        aws,
        region,
        AWS_REGIONAL_QUOTA_CONTRACT,
        identity_arn,
        global_quotas=False,
    )


def regional_elbv2_account_limits(aws: AwsCLI, region: str) -> dict[str, int]:
    response = aws.json(["elbv2", "describe-account-limits"], region=region)
    if not isinstance(response, dict):
        raise LifecycleError("AWS preflight gate elbv2-account-limits returned a malformed response")
    limits = response_object_list(response, "Limits", "elbv2-account-limits")
    expected_names = set(AWS_ELBV2_ACCOUNT_LIMIT_CONTRACT.values())
    by_name: dict[str, int] = {}
    for limit in limits:
        name, maximum = limit.get("Name"), limit.get("Max")
        if not isinstance(name, str) or not name:
            raise LifecycleError("AWS ELBv2 account limits returned a malformed Name")
        if name not in expected_names:
            continue
        if (
            name in by_name
            or not isinstance(maximum, str)
            or not re.fullmatch(r"[0-9]+", maximum)
        ):
            raise LifecycleError(f"AWS ELBv2 account limit {name!r} returned malformed or duplicate metadata")
        by_name[name] = int(maximum)
    missing = sorted(expected_names - set(by_name))
    if missing:
        raise LifecycleError(f"AWS ELBv2 account limits omitted required exact Name entries: {missing}")
    return {
        gate: by_name[name]
        for gate, name in AWS_ELBV2_ACCOUNT_LIMIT_CONTRACT.items()
    }


def aws_partition(identity_arn: str) -> str:
    parts = identity_arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or parts[1] not in AWS_GLOBAL_QUOTA_CONTROL_REGIONS:
        raise LifecycleError(
            f"AWS caller identity must use the commercial aws ARN partition: {identity_arn}"
        )
    return parts[1]


def global_service_quota_values(aws: AwsCLI, identity_arn: str) -> dict[str, dict[str, Any]]:
    region = AWS_GLOBAL_QUOTA_CONTROL_REGIONS[aws_partition(identity_arn)]
    return service_quota_values(
        aws,
        region,
        AWS_GLOBAL_QUOTA_CONTRACT,
        identity_arn,
        global_quotas=True,
    )


def s3_general_purpose_bucket_count(aws: AwsCLI, identity_arn: str) -> int:
    region = AWS_GLOBAL_QUOTA_CONTROL_REGIONS[aws_partition(identity_arn)]
    names: set[str] = set()
    seen_tokens: set[str] = set()
    token: str | None = None
    for _page in range(10_000):
        arguments = [
            "s3api",
            "list-buckets",
            "--page-size",
            "10000",
            "--max-items",
            "10000",
        ]
        if token is not None:
            arguments.extend(["--starting-token", token])
        response = aws.json(arguments, region=region)
        buckets = response.get("Buckets") if isinstance(response, dict) else None
        if (
            not isinstance(response, dict)
            or not isinstance(buckets, list)
            or any(key in response for key in ("ContinuationToken", "NextContinuationToken"))
        ):
            raise LifecycleError(f"S3 ListBuckets returned a malformed page in {region}")
        for bucket in buckets:
            name = bucket.get("Name") if isinstance(bucket, dict) else None
            if not isinstance(name, str) or not name or name in names:
                raise LifecycleError(f"S3 ListBuckets returned a malformed or duplicate bucket in {region}")
            names.add(name)
        if "NextToken" not in response:
            return len(names)
        next_token = response.get("NextToken")
        if (
            not isinstance(next_token, str)
            or not next_token
            or len(next_token) > 16_384
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in next_token)
            or next_token in seen_tokens
        ):
            raise LifecycleError(f"S3 ListBuckets returned a malformed or repeated NextToken in {region}")
        seen_tokens.add(next_token)
        token = next_token
    raise LifecycleError(f"S3 ListBuckets exceeded the defensive page limit in {region}")


def current_standard_vcpus(aws: AwsCLI, region: str) -> int:
    response = aws.json(
        [
            "ec2",
            "describe-instances",
            "--filters",
            "Name=instance-state-name,Values=pending,running",
        ],
        region=region,
    )
    reservations = response_object_list(response, "Reservations", "standard-vcpus/current-usage")
    standard_instance_types: list[str] = []
    for reservation in reservations:
        instances = response_object_list(reservation, "Instances", "standard-vcpus/current-usage")
        for instance in instances:
            state = instance.get("State")
            instance_type = instance.get("InstanceType")
            lifecycle = instance.get("InstanceLifecycle")
            placement = instance.get("Placement")
            if (
                not isinstance(state, dict)
                or state.get("Name") not in {"pending", "running"}
                or not isinstance(instance_type, str)
                or not re.fullmatch(r"[a-z0-9-]{1,32}\.[a-z0-9-]{1,32}", instance_type)
                or lifecycle not in (None, "spot", "scheduled", "capacity-block")
                or not isinstance(placement, dict)
                or placement.get("Tenancy") not in {"default", "dedicated", "host"}
            ):
                raise LifecycleError("AWS preflight gate standard-vcpus/current-usage returned malformed instance metadata")
            family = instance_type.split(".", 1)[0].lower()
            if lifecycle is None and placement["Tenancy"] == "default" and family[0] in "acdhimrtz":
                standard_instance_types.append(instance_type)
    if not standard_instance_types:
        return 0
    requested_types = sorted(set(standard_instance_types))
    metadata = response_object_list(
        aws.json(["ec2", "describe-instance-types", "--instance-types", *requested_types], region=region),
        "InstanceTypes",
        "standard-vcpus/current-usage",
    )
    by_type: dict[str, int] = {}
    for value in metadata:
        instance_type = value.get("InstanceType")
        cpu = value.get("VCpuInfo")
        default_vcpus = cpu.get("DefaultVCpus") if isinstance(cpu, dict) else None
        if (
            not isinstance(instance_type, str)
            or instance_type in by_type
            or isinstance(default_vcpus, bool)
            or not isinstance(default_vcpus, int)
            or default_vcpus <= 0
        ):
            raise LifecycleError("AWS preflight gate standard-vcpus/current-usage returned malformed type metadata")
        by_type[instance_type] = default_vcpus
    if set(by_type) != set(requested_types):
        raise LifecycleError("AWS preflight gate standard-vcpus/current-usage omitted an exact instance type")
    return sum(by_type[instance_type] for instance_type in standard_instance_types)


def validate_instance_type_offerings(config: RunConfig, aws: AwsCLI, site: str) -> list[str]:
    region = config.sites[site]["region"]
    appliance_type = str(config.raw["instance_type"])
    workload_type = str(config.raw["test_instance_type"])
    expected = {(appliance_type, str(zone)) for zone in config.sites[site]["azs"].values()}
    expected.update((workload_type, str(zone)) for zone in config.sites[site]["azs"].values())
    response = aws.json(
        [
            "ec2",
            "describe-instance-type-offerings",
            "--location-type",
            "availability-zone",
            "--filters",
            f"Name=instance-type,Values={appliance_type},{workload_type}",
        ],
        region=region,
    )
    offerings = response_object_list(response, "InstanceTypeOfferings", "instance-type-offerings")
    actual: set[tuple[str, str]] = set()
    for offering in offerings:
        candidate = (offering.get("InstanceType"), offering.get("Location"))
        if (
            not all(isinstance(value, str) and value for value in candidate)
            or candidate[0] not in {appliance_type, workload_type}
            or candidate in actual
        ):
            raise LifecycleError("AWS preflight gate instance-type-offerings returned malformed or duplicate metadata")
        actual.add((str(candidate[0]), str(candidate[1])))
    missing = sorted(expected - actual)
    if missing:
        raise LifecycleError(f"AWS preflight gate instance-type-offerings is missing required placement(s): {missing}")
    return sorted(f"{instance_type}@{zone}" for instance_type, zone in expected)


def future_appliance_role_arn(config: RunConfig, account_id: str, site: str) -> str:
    return f"arn:aws:iam::{account_id}:role/{config.run_id}-{site}-appliance"


def simulate_future_appliance_kms_policy(
    config: RunConfig,
    aws: AwsCLI,
    site: str,
    account_id: str,
    parameter_arn: str,
) -> str:
    region = str(config.sites[site]["region"])
    key_arn = str(config.sites[site]["ssm_kms_key_arn"])
    role_arn = future_appliance_role_arn(config, account_id, site)
    via_service = f"ssm.{region}.amazonaws.com"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Resource": key_arn,
                "Condition": {
                    "StringEquals": {
                        "kms:ViaService": via_service,
                        "kms:EncryptionContext:PARAMETER_ARN": parameter_arn,
                    }
                },
            }
        ],
    }
    context = simulation_context_entries(
        config,
        region=region,
        kms_via_service=via_service,
        kms_encryption_context=("PARAMETER_ARN", parameter_arn),
    )
    response = aws.json(
        [
            "iam",
            "simulate-custom-policy",
            "--policy-input-list",
            json.dumps(policy, sort_keys=True, separators=(",", ":")),
            "--action-names",
            "kms:Decrypt",
            "--resource-arns",
            key_arn,
            "--context-entries",
            json.dumps(context, sort_keys=True, separators=(",", ":")),
        ]
    )
    results = response.get("EvaluationResults") if isinstance(response, dict) else None
    if (
        not isinstance(results, list)
        or len(results) != 1
        or not isinstance(results[0], dict)
        or response.get("IsTruncated") not in (None, False)
    ):
        raise LifecycleError(f"AWS preflight gate {site}-appliance-runtime-kms returned malformed simulation")
    result = results[0]
    missing_context = result.get("MissingContextValues", [])
    if (
        result.get("EvalActionName") != "kms:Decrypt"
        or result.get("EvalDecision") != "allowed"
        or not isinstance(missing_context, list)
        or missing_context
    ):
        raise LifecycleError(
            f"AWS preflight gate {site}-appliance-runtime-kms does not allow exact KMS Decrypt through SSM"
        )
    resource_results = result.get("ResourceSpecificResults")
    if resource_results is not None and (
        not isinstance(resource_results, list)
        or len(resource_results) != 1
        or not isinstance(resource_results[0], dict)
        or resource_results[0].get("EvalResourceName") != key_arn
        or resource_results[0].get("EvalResourceDecision") != "allowed"
    ):
        raise LifecycleError(
            f"AWS preflight gate {site}-appliance-runtime-kms lacks the exact regional key decision"
        )
    return role_arn


def validate_ssm_kms_key(
    config: RunConfig,
    aws: AwsCLI,
    site: str,
    account_id: str,
    policy_source_arn: str,
) -> str:
    region = str(config.sites[site]["region"])
    expected_arn = str(config.sites[site]["ssm_kms_key_arn"])
    partition = expected_arn.split(":", 2)[1]
    response = aws.json(["kms", "describe-key", "--key-id", expected_arn], region=region)
    metadata = response.get("KeyMetadata")
    if (
        not isinstance(metadata, dict)
        or metadata.get("Arn") != expected_arn
        or metadata.get("Enabled") is not True
        or metadata.get("KeyState") != "Enabled"
        or metadata.get("KeyUsage") != "ENCRYPT_DECRYPT"
        or metadata.get("KeySpec") != "SYMMETRIC_DEFAULT"
        or metadata.get("KeyManager") != "CUSTOMER"
    ):
        raise LifecycleError(f"AWS preflight gate {site}-ssm-kms-key requires the exact enabled customer symmetric key")
    policy_response = aws.json(
        ["kms", "get-key-policy", "--key-id", expected_arn, "--policy-name", "default"],
        region=region,
    )
    policy = decode_policy_document(policy_response.get("Policy"), f"{site} SSM KMS key policy")
    parameter = next(
        value for value in intended_ssm_parameters(config, account_id) if value["site"] == site
    )
    context = {
        "aws:PrincipalArn": policy_source_arn,
        "aws:RequestedRegion": region,
        "kms:ViaService": f"ssm.{region}.{AWS_PARTITION_DNS_SUFFIXES[partition]}",
        "kms:EncryptionContextKeys": ["PARAMETER_ARN"],
        "kms:EncryptionContext:PARAMETER_ARN": str(parameter["arn"]),
    }
    for action in ("kms:Encrypt", "kms:Decrypt"):
        decision, _mode = kms_key_policy_identity_decision(
            policy,
            policy_source_arn,
            action,
            context,
        )
        if decision != "allowed":
            detail = "explicitly denies" if decision == "explicitDeny" else "does not authorize"
            raise LifecycleError(
                f"AWS preflight gate {site}-ssm-kms-key policy {detail} {action} for the exact "
                f"operator, SSM ViaService, and PARAMETER_ARN context"
            )
    appliance_role_arn = simulate_future_appliance_kms_policy(
        config,
        aws,
        site,
        account_id,
        str(parameter["arn"]),
    )
    runtime_decision, runtime_mode = kms_key_policy_identity_decision(
        policy,
        appliance_role_arn,
        "kms:Decrypt",
        {**context, "aws:PrincipalArn": appliance_role_arn},
    )
    if runtime_decision != "allowed":
        detail = "explicitly denies" if runtime_decision == "explicitDeny" else "does not authorize"
        raise LifecycleError(
            f"AWS preflight gate {site}-ssm-kms-key policy {detail} kms:Decrypt for future "
            "regional appliance role through exact SSM/PARAMETER_ARN context"
        )
    if runtime_mode not in {"direct", "account-root-delegation", "exact-wildcard-principal"}:
        raise LifecycleError(f"AWS preflight gate {site}-ssm-kms-key has no secure runtime principal path")
    return hashlib.sha256(expected_arn.encode()).hexdigest()


def regional_quota_usage(config: RunConfig, aws: AwsCLI, site: str) -> dict[str, int]:
    region = str(config.sites[site]["region"])
    vpcs = response_object_list(aws.json(["ec2", "describe-vpcs"], region=region), "Vpcs", "vpcs/current-usage")
    if any(not isinstance(value.get("VpcId"), str) for value in vpcs):
        raise LifecycleError("AWS preflight gate vpcs/current-usage returned malformed VPC metadata")

    addresses = response_object_list(
        aws.json(["ec2", "describe-addresses"], region=region), "Addresses", "elastic-ips/current-usage"
    )
    if any(not isinstance(value.get("AllocationId"), str) for value in addresses):
        raise LifecycleError("AWS preflight gate elastic-ips/current-usage returned malformed address metadata")

    gateways = response_object_list(
        aws.json(["ec2", "describe-nat-gateways"], region=region),
        "NatGateways",
        "nat-gateways-per-availability-zone/current-usage",
    )
    active_zonal_gateways: list[dict[str, Any]] = []
    excluded_regional_gateways = 0
    valid_states = {"available", "pending", "deleting", "deleted", "failed"}
    capacity_states = {"available", "pending", "deleting"}
    gateway_ids: set[str] = set()
    for gateway in gateways:
        gateway_id = gateway.get("NatGatewayId")
        state = gateway.get("State")
        availability_mode = gateway.get("AvailabilityMode")
        if (
            not isinstance(gateway_id, str)
            or not re.fullmatch(r"nat-(?:[0-9a-f]{8}|[0-9a-f]{17})", gateway_id)
            or gateway_id in gateway_ids
            or not isinstance(state, str)
            or state not in valid_states
            or not isinstance(availability_mode, str)
            or availability_mode not in {"zonal", "regional"}
        ):
            raise LifecycleError("AWS preflight gate NAT current usage returned malformed gateway metadata")
        gateway_ids.add(gateway_id)
        if availability_mode == "zonal":
            subnet_id = gateway.get("SubnetId")
            if not isinstance(subnet_id, str) or not re.fullmatch(
                r"subnet-(?:[0-9a-f]{8}|[0-9a-f]{17})",
                subnet_id,
            ):
                raise LifecycleError("AWS preflight gate NAT current usage omitted an exact zonal subnet identity")
            if state in capacity_states:
                active_zonal_gateways.append(gateway)
            continue

        vpc_id = gateway.get("VpcId")
        route_table_id = gateway.get("RouteTableId")
        gateway_addresses = gateway.get("NatGatewayAddresses")
        if (
            "SubnetId" in gateway
            or not isinstance(vpc_id, str)
            or not re.fullmatch(r"vpc-(?:[0-9a-f]{8}|[0-9a-f]{17})", vpc_id)
            or not isinstance(route_table_id, str)
            or not re.fullmatch(r"rtb-(?:[0-9a-f]{8}|[0-9a-f]{17})", route_table_id)
            or not isinstance(gateway_addresses, list)
            or not gateway_addresses
            or not all(isinstance(address, dict) for address in gateway_addresses)
            or any(
                not isinstance(address.get("AvailabilityZone"), str)
                or not re.fullmatch(
                    rf"{re.escape(region)}[a-z]",
                    address["AvailabilityZone"],
                )
                for address in gateway_addresses
            )
        ):
            raise LifecycleError("AWS preflight gate NAT current usage returned malformed regional gateway metadata")
        if state in capacity_states:
            excluded_regional_gateways += 1

    nat_subnet_ids = sorted({str(value["SubnetId"]) for value in active_zonal_gateways})
    subnet_azs: dict[str, str] = {}
    if nat_subnet_ids:
        subnets = response_object_list(
            aws.json(["ec2", "describe-subnets", "--subnet-ids", *nat_subnet_ids], region=region),
            "Subnets",
            "nat-gateways-per-availability-zone/current-usage",
        )
        for subnet in subnets:
            subnet_id, zone = subnet.get("SubnetId"), subnet.get("AvailabilityZone")
            if (
                not isinstance(subnet_id, str)
                or not re.fullmatch(r"subnet-(?:[0-9a-f]{8}|[0-9a-f]{17})", subnet_id)
                or not isinstance(zone, str)
                or not re.fullmatch(rf"{re.escape(region)}[a-z]", zone)
                or subnet_id in subnet_azs
            ):
                raise LifecycleError("AWS preflight gate NAT current usage returned malformed subnet metadata")
            subnet_azs[subnet_id] = zone
        if set(subnet_azs) != set(nat_subnet_ids):
            raise LifecycleError("AWS preflight gate NAT current usage omitted an exact subnet")
    target_zone = str(next(iter(config.sites[site]["azs"].values())))

    load_balancers = response_object_list(
        aws.json(["elbv2", "describe-load-balancers"], region=region),
        "LoadBalancers",
        "gateway-load-balancers/current-usage",
    )
    load_balancer_arns: set[str] = set()
    gateway_load_balancers = 0
    for value in load_balancers:
        arn, load_balancer_type = value.get("LoadBalancerArn"), value.get("Type")
        if (
            not isinstance(arn, str)
            or not arn
            or arn in load_balancer_arns
            or not isinstance(load_balancer_type, str)
            or not load_balancer_type
        ):
            raise LifecycleError("AWS preflight gate gateway-load-balancers/current-usage returned malformed metadata")
        load_balancer_arns.add(arn)
        gateway_load_balancers += load_balancer_type == "gateway"
    target_groups = response_object_list(
        aws.json(["elbv2", "describe-target-groups"], region=region),
        "TargetGroups",
        "target-groups/current-usage",
    )
    target_group_arns: set[str] = set()
    geneve_target_groups = 0
    for value in target_groups:
        arn, protocol, target_type = (
            value.get("TargetGroupArn"),
            value.get("Protocol"),
            value.get("TargetType"),
        )
        if (
            not isinstance(arn, str)
            or not arn
            or arn in target_group_arns
            or not isinstance(target_type, str)
            or not target_type
            or (protocol is None and target_type != "lambda")
            or (protocol is not None and (not isinstance(protocol, str) or not protocol))
        ):
            raise LifecycleError("AWS preflight gate target-groups/current-usage returned malformed metadata")
        target_group_arns.add(arn)
        geneve_target_groups += isinstance(protocol, str) and protocol.upper() == "GENEVE"
    endpoint_services = response_object_list(
        aws.json(["ec2", "describe-vpc-endpoint-service-configurations"], region=region),
        "ServiceConfigurations",
        "vpc-endpoint-services/current-usage",
    )
    endpoint_service_ids: set[str] = set()
    endpoint_service_count = 0
    for service in endpoint_services:
        service_id, service_state = service.get("ServiceId"), service.get("ServiceState")
        if (
            not isinstance(service_id, str)
            or not service_id
            or service_id in endpoint_service_ids
            or not isinstance(service_state, str)
            or service_state.lower() not in {"pending", "available", "deleting", "deleted", "failed"}
        ):
            raise LifecycleError("AWS preflight gate vpc-endpoint-services/current-usage returned malformed metadata")
        endpoint_service_ids.add(service_id)
        endpoint_service_count += 1
    log_groups = response_object_list(
        aws.json(["logs", "describe-log-groups"], region=region),
        "logGroups",
        "cloudwatch-log-groups/current-usage",
    )
    if any(not isinstance(value.get("logGroupName"), str) for value in log_groups):
        raise LifecycleError("AWS preflight gate cloudwatch-log-groups/current-usage returned malformed metadata")
    return {
        "cloudwatch-log-groups": len(log_groups),
        "elastic-ips": len(addresses),
        "flow-logs-per-resource": 0,
        "gateway-load-balancer-endpoints-per-vpc": 0,
        "gateway-load-balancers": gateway_load_balancers,
        "gateway-load-balancers-per-vpc": 0,
        "geneve-target-groups": geneve_target_groups,
        "listeners-per-gateway-load-balancer": 0,
        "nat-gateways-per-availability-zone": sum(
            subnet_azs[str(value["SubnetId"])] == target_zone for value in active_zonal_gateways
        ),
        "excluded_regional_nat_gateways": excluded_regional_gateways,
        "standard-vcpus": current_standard_vcpus(aws, region),
        "target-groups": len(target_groups),
        "targets-per-availability-zone-per-gateway-load-balancer": 0,
        "targets-per-gateway-load-balancer": 0,
        "vpc-endpoint-services": endpoint_service_count,
        "vpcs": len(vpcs),
    }


def capacity_record(
    gate: str,
    *,
    service: str,
    name: str,
    source: str,
    code: str | None,
    limit: int | float,
    used: int,
    required: int,
) -> dict[str, Any]:
    numeric_limit = float(limit)
    available = numeric_limit - used
    if available < required:
        raise LifecycleError(
            f"AWS quota preflight gate {gate} is too low: limit={numeric_limit:g} "
            f"used={used} required={required}"
        )
    return {
        "service": service,
        "quota_name": name,
        "quota_code": code,
        "source": source,
        "limit": normalized_capacity_number(numeric_limit),
        "used": used,
        "required": required,
        "available": normalized_capacity_number(available),
    }


def quota_capacity_record(
    gate: str,
    quota: dict[str, Any],
    *,
    used: int,
    required: int,
    contract: dict[str, tuple[str, str, str]] = AWS_REGIONAL_QUOTA_CONTRACT,
) -> dict[str, Any]:
    service, expected_code, documented_name = contract[gate]
    return capacity_record(
        gate,
        service=service,
        name=documented_name,
        source="servicequotas:GetServiceQuota",
        code=expected_code,
        limit=float(quota["Value"]),
        used=used,
        required=required,
    )


def validate_aws_preflight_summary(summary: Any, config: RunConfig, account_id: str) -> None:
    if not isinstance(summary, dict) or set(summary) != {
        "schema",
        "account_id",
        "principal",
        "actions",
        "regions",
        "global_quotas",
        "iam_capacity",
    }:
        raise LifecycleError("AWS preflight summary has an invalid top-level schema")
    if summary.get("schema") != 1 or summary.get("account_id") != account_id:
        raise LifecycleError("AWS preflight summary account identity is invalid")
    principal = summary.get("principal")
    if (
        not isinstance(principal, dict)
        or set(principal) != {"kind", "policy_source_sha256"}
        or principal.get("kind") not in {"user", "role", "assumed-role"}
        or not isinstance(principal.get("policy_source_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", principal["policy_source_sha256"])
    ):
        raise LifecycleError("AWS preflight summary principal identity is invalid")
    actions = summary.get("actions")
    expected_run_instances_dry_run = {
        site: {
            "target": str(config.raw["instance_type"]),
            "ingress_router": str(config.raw["instance_type"]),
            "workload": str(config.raw["test_instance_type"]),
        }
        for site in ("west", "east")
    }
    if (
        not isinstance(actions, dict)
        or set(actions)
        != {
            "operator",
            "operator_simulated",
            "operator_decision",
            "run_instances_dry_run",
            "flow_log_delivery_role",
        }
        or actions.get("operator") != list(AWS_OPERATOR_ACTIONS)
        or actions.get("operator_simulated") != list(AWS_IAM_SIMULATED_OPERATOR_ACTIONS)
        or actions.get("operator_decision") != "allowed"
        or actions.get("run_instances_dry_run") != expected_run_instances_dry_run
        or actions.get("flow_log_delivery_role") != list(AWS_FLOW_LOG_DELIVERY_ACTIONS)
    ):
        raise LifecycleError("AWS preflight summary action contract is invalid")
    global_quotas = summary.get("global_quotas")
    if not isinstance(global_quotas, dict) or set(global_quotas) != set(AWS_GLOBAL_QUOTA_CONTRACT):
        raise LifecycleError("AWS preflight summary global quota contract is invalid")
    for gate, (service, quota_code, documented_name) in AWS_GLOBAL_QUOTA_CONTRACT.items():
        record = global_quotas[gate]
        if (
            not isinstance(record, dict)
            or set(record)
            != {"service", "quota_name", "quota_code", "source", "limit", "used", "required", "available"}
            or record.get("service") != service
            or record.get("quota_name") != documented_name
            or record.get("quota_code") != quota_code
            or record.get("source") != "servicequotas:GetServiceQuota"
            or record.get("required") != 1
            or isinstance(record.get("limit"), bool)
            or not isinstance(record.get("limit"), (int, float))
            or isinstance(record.get("used"), bool)
            or not isinstance(record.get("used"), int)
            or record["used"] < 0
            or isinstance(record.get("available"), bool)
            or not isinstance(record.get("available"), (int, float))
            or not math.isfinite(float(record["limit"]))
            or not math.isclose(float(record["available"]), float(record["limit"]) - record["used"])
            or float(record["available"]) < 1
        ):
            raise LifecycleError(f"AWS preflight summary global quota gate {gate} is invalid")
    regions = summary.get("regions")
    expected_regions = {str(config.sites[site]["region"]): site for site in ("west", "east")}
    if not isinstance(regions, dict) or set(regions) != set(expected_regions):
        raise LifecycleError("AWS preflight summary regional identity is invalid")
    for region, site in expected_regions.items():
        value = regions[region]
        if not isinstance(value, dict) or set(value) != {
            "site",
            "planned_instances",
            "instance_vcpus",
            "instance_offerings",
            "ssm_kms_key_sha256",
            "excluded_regional_nat_gateways",
            "quotas",
        }:
            raise LifecycleError(f"AWS preflight summary for {region} has an invalid schema")
        instance_vcpus = value.get("instance_vcpus")
        if (
            value.get("site") != site
            or value.get("planned_instances") != 6
            or not isinstance(instance_vcpus, dict)
            or set(instance_vcpus) != {"target", "ingress_router", "workload"}
            or any(isinstance(number, bool) or not isinstance(number, int) or number <= 0 for number in instance_vcpus.values())
            or isinstance(value.get("excluded_regional_nat_gateways"), bool)
            or not isinstance(value.get("excluded_regional_nat_gateways"), int)
            or value["excluded_regional_nat_gateways"] < 0
        ):
            raise LifecycleError(f"AWS preflight summary for {region} has invalid instance capacity")
        expected_offerings = {
            *(f"{config.raw['instance_type']}@{zone}" for zone in config.sites[site]["azs"].values()),
            *(f"{config.raw['test_instance_type']}@{zone}" for zone in config.sites[site]["azs"].values()),
        }
        if value.get("instance_offerings") != sorted(expected_offerings):
            raise LifecycleError(f"AWS preflight summary for {region} has invalid instance offerings")
        if value.get("ssm_kms_key_sha256") != hashlib.sha256(
            str(config.sites[site]["ssm_kms_key_arn"]).encode()
        ).hexdigest():
            raise LifecycleError(f"AWS preflight summary for {region} has an invalid SSM KMS key identity")
        quotas = value.get("quotas")
        expected_capacity: dict[str, tuple[str, str, str | None, str, int | None]] = {
            gate: (service, name, code, "servicequotas:GetServiceQuota", None)
            for gate, (service, code, name) in AWS_REGIONAL_QUOTA_CONTRACT.items()
        }
        expected_capacity.update(
            {
                gate: (
                    "elasticloadbalancing",
                    name,
                    None,
                    "elbv2:DescribeAccountLimits",
                    None,
                )
                for gate, name in AWS_ELBV2_ACCOUNT_LIMIT_CONTRACT.items()
            }
        )
        expected_capacity.update(
            {
                gate: (service, name, None, source, limit)
                for gate, (service, name, limit, source) in AWS_STRUCTURAL_CAPACITY_CONTRACT.items()
            }
        )
        if not isinstance(quotas, dict) or set(quotas) != set(expected_capacity):
            raise LifecycleError(f"AWS preflight summary for {region} has an incomplete quota contract")
        for gate, (service, quota_name, quota_code, source, fixed_limit) in expected_capacity.items():
            record = quotas[gate]
            required = 2 * (instance_vcpus["target"] + instance_vcpus["ingress_router"] + instance_vcpus["workload"]) if gate == "standard-vcpus" else 1
            if (
                not isinstance(record, dict)
                or set(record)
                != {"service", "quota_name", "quota_code", "source", "limit", "used", "required", "available"}
                or record.get("service") != service
                or record.get("quota_name") != quota_name
                or record.get("quota_code") != quota_code
                or record.get("source") != source
                or record.get("required") != required
                or isinstance(record.get("limit"), bool)
                or not isinstance(record.get("limit"), (int, float))
                or isinstance(record.get("used"), bool)
                or not isinstance(record.get("used"), int)
                or record["used"] < 0
                or isinstance(record.get("available"), bool)
                or not isinstance(record.get("available"), (int, float))
                or not math.isfinite(float(record["limit"]))
                or not math.isfinite(float(record["available"]))
                or (fixed_limit is not None and record["limit"] != fixed_limit)
                or not math.isclose(float(record["available"]), float(record["limit"]) - record["used"])
                or float(record["available"]) < required
            ):
                raise LifecycleError(f"AWS preflight summary quota gate {gate} is invalid")
    iam_capacity = summary.get("iam_capacity")
    if not isinstance(iam_capacity, dict) or set(iam_capacity) != set(AWS_IAM_CAPACITY_CONTRACT):
        raise LifecycleError("AWS preflight summary IAM capacity contract is invalid")
    for gate, (_, _, required) in AWS_IAM_CAPACITY_CONTRACT.items():
        record = iam_capacity[gate]
        if (
            not isinstance(record, dict)
            or set(record) != {"source", "limit", "used", "required", "available"}
            or record.get("source") != "iam:GetAccountSummary"
            or record.get("required") != required
            or any(isinstance(record.get(field), bool) or not isinstance(record.get(field), int) for field in ("limit", "used", "available"))
            or record["limit"] < 0
            or record["used"] < 0
            or record["available"] != record["limit"] - record["used"]
            or record["available"] < required
        ):
            raise LifecycleError(f"AWS preflight summary IAM capacity gate {gate} is invalid")
    serialized = json.dumps(summary, sort_keys=True, separators=(",", ":"))
    if redact(serialized) != serialized or "oauth" in serialized.lower():
        raise LifecycleError("AWS preflight summary contains prohibited credential material")


def aws_capability_quota_preflight(
    config: RunConfig,
    aws: AwsCLI,
    instance_vcpus: dict[str, dict[str, int]],
    artifact: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    identity = aws_caller_identity(aws)
    configured_partition = str(config.backend["kms_key_arn"]).split(":", 2)[1]
    if aws_partition(identity["arn"]) != configured_partition:
        raise LifecycleError("AWS caller and all configured resources must use the commercial aws partition")
    principal_kind, policy_source_arn = resolve_iam_simulation_principal(aws, identity)
    run_instances_dry_run = run_instances_dry_run_preflight(config, aws)
    simulate_operator_actions(aws, policy_source_arn, config, identity["account_id"], artifact)

    account_summary = aws.json(["iam", "get-account-summary"]).get("SummaryMap")
    if not isinstance(account_summary, dict) or not all(
        isinstance(key, str) and isinstance(value, int) and not isinstance(value, bool)
        for key, value in account_summary.items()
    ):
        raise LifecycleError("AWS preflight IAM capacity gate returned a malformed account summary")
    iam_capacity: dict[str, dict[str, Any]] = {}
    for gate, (usage_field, quota_field, required) in AWS_IAM_CAPACITY_CONTRACT.items():
        used, limit = account_summary.get(usage_field), account_summary.get(quota_field)
        if not isinstance(used, int) or not isinstance(limit, int) or used < 0 or limit < 0:
            raise LifecycleError(f"AWS preflight IAM capacity gate {gate} is unavailable")
        available = limit - used
        if available < required:
            raise LifecycleError(
                f"AWS preflight IAM capacity gate {gate} is too low: limit={limit} used={used} required={required}"
            )
        iam_capacity[gate] = {
            "source": "iam:GetAccountSummary",
            "limit": limit,
            "used": used,
            "required": required,
            "available": available,
        }

    global_quota_values = global_service_quota_values(aws, str(identity["arn"]))
    bucket_count = s3_general_purpose_bucket_count(aws, str(identity["arn"]))
    global_quotas = {
        "s3-artifact-buckets": quota_capacity_record(
            "s3-artifact-buckets",
            global_quota_values["s3-artifact-buckets"],
            used=bucket_count,
            required=1,
            contract=AWS_GLOBAL_QUOTA_CONTRACT,
        )
    }

    regions: dict[str, dict[str, Any]] = {}
    for site in ("west", "east"):
        region = str(config.sites[site]["region"])
        type_values = instance_vcpus.get(region)
        appliance_type = str(config.raw["instance_type"])
        workload_type = str(config.raw["test_instance_type"])
        if not isinstance(type_values, dict) or set(type_values) != {appliance_type, workload_type}:
            raise LifecycleError(f"AWS preflight for {region} lacks exact instance vCPU metadata")
        per_role_vcpus = {
            "target": type_values[appliance_type],
            "ingress_router": type_values[appliance_type],
            "workload": type_values[workload_type],
        }
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in per_role_vcpus.values()):
            raise LifecycleError(f"AWS preflight for {region} has invalid instance vCPU metadata")
        ssm_kms_key_sha256 = validate_ssm_kms_key(
            config,
            aws,
            site,
            identity["account_id"],
            policy_source_arn,
        )
        offerings = validate_instance_type_offerings(config, aws, site)
        quota_values = regional_service_quota_values(aws, region, identity["arn"])
        account_limits = regional_elbv2_account_limits(aws, region)
        usage = regional_quota_usage(config, aws, site)
        quotas: dict[str, dict[str, Any]] = {}
        for gate in sorted(AWS_REGIONAL_QUOTA_CONTRACT):
            required = 2 * (per_role_vcpus["target"] + per_role_vcpus["ingress_router"] + per_role_vcpus["workload"]) if gate == "standard-vcpus" else 1
            quotas[gate] = quota_capacity_record(gate, quota_values[gate], used=usage[gate], required=required)
        for gate, name in sorted(AWS_ELBV2_ACCOUNT_LIMIT_CONTRACT.items()):
            quotas[gate] = capacity_record(
                gate,
                service="elasticloadbalancing",
                name=name,
                source="elbv2:DescribeAccountLimits",
                code=None,
                limit=account_limits[gate],
                used=usage[gate],
                required=1,
            )
        for gate, (service, name, limit, source) in sorted(AWS_STRUCTURAL_CAPACITY_CONTRACT.items()):
            quotas[gate] = capacity_record(
                gate,
                service=service,
                name=name,
                source=source,
                code=None,
                limit=limit,
                used=usage[gate],
                required=1,
            )
        regions[region] = {
            "site": site,
            "planned_instances": 6,
            "instance_vcpus": per_role_vcpus,
            "instance_offerings": offerings,
            "ssm_kms_key_sha256": ssm_kms_key_sha256,
            "excluded_regional_nat_gateways": usage["excluded_regional_nat_gateways"],
            "quotas": quotas,
        }
    summary = {
        "schema": 1,
        "account_id": identity["account_id"],
        "principal": {
            "kind": principal_kind,
            "policy_source_sha256": hashlib.sha256(policy_source_arn.encode()).hexdigest(),
        },
        "actions": {
            "operator": list(AWS_OPERATOR_ACTIONS),
            "operator_simulated": list(AWS_IAM_SIMULATED_OPERATOR_ACTIONS),
            "operator_decision": "allowed",
            "run_instances_dry_run": run_instances_dry_run,
            "flow_log_delivery_role": list(AWS_FLOW_LOG_DELIVERY_ACTIONS),
        },
        "regions": regions,
        "global_quotas": global_quotas,
        "iam_capacity": iam_capacity,
    }
    validate_aws_preflight_summary(summary, config, identity["account_id"])
    return identity["account_id"], summary


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
        "symmetric_topology": {"version": 2, "sites": copy.deepcopy(config.sites)},
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
        "envelope_routing_table_id": envelope["routing_table_id"],
        "envelope_routing_rule_priority": envelope["routing_rule_priority"],
        "estimated_fixed_hourly_usd": config.raw["cost"]["estimated_fixed_hourly_usd"],
        "approved_max_fixed_hourly_usd": config.raw["cost"]["approved_max_fixed_hourly_usd"],
        "e2e_load_profile": dict(config.raw["e2e_load_profile"]),
    }


def new_manifest(config: RunConfig, artifact: dict[str, Any], account_id: str) -> dict[str, Any]:
    aws_preflight = artifact.get("aws_preflight")
    validate_aws_preflight_summary(aws_preflight, config, account_id)
    parameters = intended_ssm_parameters(config, account_id)
    artifact_bucket = f"{config.run_id}-{account_id}-{config.sites['west']['region']}-artifact"
    artifact_key = f"artifacts/{artifact['revision']}/envelope-linux-{config.architecture}"
    return {
        "schema": SCHEMA,
        "run_id": config.run_id,
        "expires_at": config.expires_at,
        "configuration_sha256": config.config_identity,
        "aws_account_id": account_id,
        "aws_preflight": copy.deepcopy(aws_preflight),
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
    site_cidrs = config.site_cidrs
    advertised = site_cidrs["west"] + site_cidrs["east"]
    validate_tailnet_policy(
        policy,
        tag=str(config.tailnet["tag"]),
        tag_owners=[str(value) for value in config.tailnet["tag_owners"]],
        advertised_routes=advertised,
        site_cidrs=site_cidrs,
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
    instance_vcpus = validate_aws_metadata(config, aws)
    account_id, aws_preflight = aws_capability_quota_preflight(config, aws, instance_vcpus, artifact)
    tailnet_preflight(config, tailscale)
    return {**artifact, "aws_preflight": aws_preflight}, account_id


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


def manifest_create_collision(error: CommandError) -> bool:
    try:
        service_index = error.args_list.index("s3api")
        condition_index = error.args_list.index("--if-none-match")
    except ValueError:
        return False
    return (
        error.args_list[service_index : service_index + 2] == ["s3api", "put-object"]
        and condition_index + 1 < len(error.args_list)
        and error.args_list[condition_index + 1] == "*"
        and any(
            marker in error.raw_stderr
            for marker in ("PreconditionFailed", "ConditionalRequestConflict", "status code: 409", "status code: 412")
        )
    )


@serialized_run_operation
def prepare(config: RunConfig, aws: AwsCLI, tailscale: TailscaleAPI, run_dir: pathlib.Path) -> dict[str, Any]:
    artifact, account_id = run_preflight(config, aws, tailscale)
    store = ManifestStore(config, aws, run_dir)
    manifest = new_manifest(config, artifact, account_id)
    manifest["prepare_started_at"] = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    try:
        store.write(manifest, if_none_match=True)
    except CommandError as error:
        if manifest_create_collision(error):
            with _CONCURRENT_PREPARE_RUNS_GUARD:
                _CONCURRENT_PREPARE_RUNS.add(run_dir.expanduser().resolve())
            raise ConcurrentLifecycleError("durable run manifest is already owned by another lifecycle process") from None
        raise
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
  for_each         = aws_instance.envelope_target_west
  target_group_arn = aws_lb_target_group.west.arn
  target_id        = each.value.id
}''',
        '''resource "aws_lb_target_group_attachment" "east" {
  provider         = aws.east
  for_each         = aws_instance.envelope_target_east
  target_group_arn = aws_lb_target_group.east.arn
  target_id        = each.value.id
}''',
    )
    raw_topology = (terraform_dir / "topology.tf").read_text()
    if "<<" in raw_topology or "\\u" in raw_topology or "\\U" in raw_topology:
        raise LifecycleError("reviewed GWLB source contains a prohibited heredoc or escaped label")
    topology = strip_hcl_comments(raw_topology)
    if any(topology.count(block) != 1 for block in expected_blocks):
        raise LifecycleError("reviewed Terraform source does not use exact direct regional target attachments")
    for site in ("west", "east"):
        if len(re.findall(rf'resource\s+"aws_lb_target_group_attachment"\s+"{site}"\s*\{{', topology)) != 1:
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
    entries: list[tuple[str, str, str]] = []
    prefix = source_prefix.as_posix().rstrip("/") + "/"
    for line in listing.splitlines():
        try:
            metadata, tracked_path = line.split("\t", 1)
            mode, object_type, object_id = metadata.split(" ", 2)
        except ValueError as error:
            raise LifecycleError("Git returned an invalid Terraform source tree entry") from error
        if mode not in {"100644", "100755"} or object_type != "blob" or not tracked_path.startswith(prefix):
            raise LifecycleError("reviewed Terraform source tree contains an unsupported entry")
        relative = tracked_path.removeprefix(prefix)
        if not relative or pathlib.PurePosixPath(relative).is_absolute() or ".." in pathlib.PurePosixPath(relative).parts:
            raise LifecycleError("reviewed Terraform source tree contains an unsafe path")
        entries.append((relative, object_id, mode))
    if not entries or not any(path.endswith(".tf") for path, _object_id, _mode in entries) or not any(
        path == ".terraform.lock.hcl" for path, _object_id, _mode in entries
    ):
        raise LifecycleError("reviewed Terraform source tree is incomplete")
    snapshot = (run_dir / "terraform-source").resolve()
    if snapshot.parent != run_dir:
        raise LifecycleError("reviewed Terraform source snapshot escaped the protected run directory")
    if snapshot.exists():
        shutil.rmtree(snapshot)
    snapshot.mkdir(mode=0o700, parents=True)
    for relative, object_id, mode in entries:
        destination = snapshot / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.write_text(
            runner.run(["git", "-C", str(repository), "cat-file", "blob", object_id], env=git_env)
        )
        os.chmod(destination, 0o700 if mode == "100755" else 0o600)
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


def validate_symmetric_saved_plan(document: Any, config: RunConfig) -> list[str]:
    """Check the reviewed v2 output contract before a protected apply."""

    if not isinstance(document, dict):
        return ["saved plan is not an object"]
    planned = document.get("planned_values")
    outputs = planned.get("outputs") if isinstance(planned, dict) else None
    if not isinstance(outputs, dict):
        return ["saved plan omits planned outputs"]
    required_outputs = {
        "artifact_identity",
        "cost_profile",
        "e2e_load_profile",
        "envelope_runtime_config",
        "flow_log_evidence",
        "gwlb_endpoint_ids",
        "gwlb_target_group_arns",
        "instance_ids",
        "symmetric_topology",
        "vpc_ids",
        "workload_instances",
    }
    runtime = outputs.get("envelope_runtime_config", {}).get("value") if isinstance(outputs.get("envelope_runtime_config"), dict) else None
    cost = outputs.get("cost_profile", {}).get("value") if isinstance(outputs.get("cost_profile"), dict) else None
    artifact = outputs.get("artifact_identity", {}).get("value") if isinstance(outputs.get("artifact_identity"), dict) else None
    failures: list[str] = []
    if set(outputs) != required_outputs:
        failures.append("saved plan does not declare the complete symmetric deployment output contract")
    if not isinstance(runtime, dict) or set(runtime) != set(DEPLOYMENT_SITES):
        failures.append("saved plan omits symmetric runtime identities")
    else:
        for site in DEPLOYMENT_SITES:
            value = runtime.get(site)
            expected = config.sites[site]
            if not isinstance(value, dict) or any(
                value.get(key) != expected_value
                for key, expected_value in {
                    "config_version": 2,
                    "local_site_cidrs": expected["local_site_cidrs"],
                    "remote_site_cidrs": expected["remote_site_cidrs"],
                }.items()
            ):
                failures.append(f"saved plan {site} runtime does not match symmetric topology v2")
    if not isinstance(cost, dict) or cost.get("profile") != "symmetric-gwlb-ha-v2":
        failures.append("saved plan does not declare the symmetric HA cost profile")
    if not isinstance(artifact, dict) or artifact.get("architecture") != config.architecture or artifact.get(
        "ec2_arch"
    ) != ARCHITECTURES[config.architecture] or not re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("sha256", ""))) or not re.fullmatch(
        r"[0-9a-f]{40}", str(artifact.get("revision", ""))
    ):
        failures.append("saved plan omits a valid reviewed artifact identity")
    return failures


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
        if re.fullmatch(r'aws_instance\.envelope_target_(west|east)\["[a-z][a-z0-9-]{0,15}"\]', replace_address) is None:
            raise LifecycleError("replacement address must be one exact symmetric Envelope target instance")
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
    failures = validate_symmetric_saved_plan(document, config)
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
    apply_claimed_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    manifest["apply_claimed_at"] = apply_claimed_at
    store.write(manifest, if_match=store.remote_etag)
    try:
        source_dir, materialized_identity = materialize_durable_terraform_source(durable_source, run_dir)
        if materialized_identity != source_identity:
            raise LifecycleError("apply Terraform source bundle changed after its durable claim")
        terraform_init(config, aws, runner, run_dir, source_dir)
        replacement = saved.get("replacement")
        if replacement:
            if tailscale_factory is None:
                raise LifecycleError("target replacement requires an exact Tailnet retirement authority")
            retire_replacement_devices(tailscale_factory(), store, manifest, str(replacement))
        manifest["tailnet"]["nodes_expected"] = True
        manifest["phase"] = "apply_started"
        store.write(manifest)
        env = child_environment(config, TF_DATA_DIR=str((run_dir / "terraform-data").resolve()), TF_IN_AUTOMATION="1")
        runner.run(["terraform", "apply", "-input=false", str(destination)], env=env, cwd=source_dir)
        output = runner.run(["terraform", "output", "-json"], env=env, cwd=source_dir)
        deployment = parse_deployment_json(output, "Terraform output after apply")
        validate_symmetric_deployment_output(deployment, config)
        deployment_path = run_dir / "deployment.json"
        deployment_path.write_text(json.dumps(deployment, sort_keys=True, separators=(",", ":")) + "\n")
        os.chmod(deployment_path, 0o600)
        manifest["phase"] = "applied"
        manifest["saved_plan"]["applied"] = True
        manifest["saved_plan"]["applied_at"] = apply_claimed_at
        manifest.pop("apply_claimed_at", None)
        manifest["deployment"] = deployment
        completion_etag = store.remote_etag
        store.write(manifest, if_match=completion_etag)
        return deployment
    except Exception as error:
        if manifest["saved_plan"].get("applied") is True:
            try:
                store.write(manifest, if_match=completion_etag)
            except Exception as persistence_error:
                raise LifecycleError(
                    f"Terraform apply completed but its durable applied boundary could not be persisted: {persistence_error}"
                ) from error
            return deployment
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
done
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

WORKLOAD_DIAGNOSTIC_COMMANDS = [
    "set +e",
    "/usr/bin/timeout --signal=TERM --kill-after=2s 20s cloud-init status --long",
    "/usr/bin/timeout --signal=TERM --kill-after=2s 20s systemctl status amazon-ssm-agent.service --no-pager --full",
    "/usr/bin/timeout --signal=TERM --kill-after=2s 20s /usr/sbin/ip -brief address show",
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


def wait_for_instance(
    aws: AwsCLI,
    *,
    region: str,
    instance_id: str,
    deadline: float,
    readiness_commands: list[str] | None = READINESS_COMMANDS,
    node_label: str = "instance",
    sleep: Any = time.sleep,
) -> None:
    while time.monotonic() < deadline:
        response = aws.json(
            ["ssm", "describe-instance-information", "--filters", f"Key=InstanceIds,Values={instance_id}"], region=region
        )
        entries = response.get("InstanceInformationList", [])
        if (
            len(entries) == 1
            and entries[0].get("PingStatus") == "Online"
            and entries[0].get("InstanceId", instance_id) == instance_id
        ):
            if readiness_commands is None:
                return
            payload = json.dumps(
                {"commands": readiness_commands, "executionTimeout": ["750"]}, separators=(",", ":")
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
            if (
                not isinstance(command_id, str)
                or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", command_id)
                or redact(command_id) != command_id
            ):
                raise LifecycleError(f"SSM readiness command for {node_label} in {region} returned no valid command id")
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
                            redact(
                                f"SSM readiness polling and cancellation failed for {node_label} in {region}: "
                                f"{error}; {cancellation_error}"
                            )
                        ) from None
                    raise LifecycleError(
                        redact(f"SSM readiness polling failed for {node_label} in {region} after confirmed stop: {error}")
                    ) from None
                status = invocation.get("Status")
                if status == "Success":
                    return
                if status in {"Cancelled", "Failed", "TimedOut"}:
                    raise LifecycleError(
                        redact(
                            f"SSM readiness failed for {node_label} in {region}: "
                            f"{invocation.get('StandardErrorContent', '')}"
                        )
                    )
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
                raise LifecycleError(
                    redact(
                        f"SSM readiness timed out for {node_label} in {region} and command cancellation failed: {error}"
                    )
                ) from None
            raise LifecycleError(f"SSM readiness timed out for {node_label} in {region}")
        sleep(5)
    raise LifecycleError(f"SSM readiness timed out for {node_label} in {region}")


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
            state = str(health.get("State", "unknown"))
            last_state = state if re.fullmatch(r"[a-z-]{1,64}", state) else "invalid"
            if last_state == "healthy":
                return
        sleep(5)
    raise LifecycleError(f"GWLB target in {region} did not become healthy; last state={last_state}")


def collect_diagnostics(
    aws: AwsCLI,
    site: dict[str, str],
    instance_id: str,
    *,
    commands: list[str] | None = None,
    sleep: Any = time.sleep,
) -> dict[str, str]:
    diagnostic_commands = ["/usr/local/sbin/envelope-diagnostics"] if commands is None else list(commands)
    payload = json.dumps(
        {"commands": diagnostic_commands, "executionTimeout": ["90"]},
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
    if not re.fullmatch(r"[A-Za-z0-9-]{1,128}", command_id) or redact(command_id) != command_id:
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
            safe_status = status if re.fullmatch(r"[A-Za-z]{1,64}", status) else "Unknown"
            return {
                "command_id": command_id,
                "status": safe_status,
                "stdout": redact(str(invocation.get("StandardOutputContent", "")))[:32768],
                "stderr": redact(str(invocation.get("StandardErrorContent", "")))[:32768],
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


def parse_deployment_json(value: str, description: str = "deployment output") -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise LifecycleError(f"{description} contains a duplicate object key")
            result[key] = item
        return result

    try:
        document = json.loads(value, object_pairs_hook=unique_object)
    except json.JSONDecodeError:
        raise LifecycleError(f"{description} is not valid JSON") from None
    if not isinstance(document, dict):
        raise LifecycleError(f"{description} must be a JSON object")
    return document


def validate_symmetric_deployment_output(document: dict[str, Any], config: RunConfig) -> None:
    """Accept the complete v2 Terraform output contract after apply."""

    failures = validate_symmetric_saved_plan({"planned_values": {"outputs": document}}, config)
    if failures:
        raise LifecycleError("deployment output failed symmetric validation: " + "; ".join(failures))


def deployment_values(
    document: dict[str, Any],
    *,
    expected_sites: dict[str, dict[str, Any]] | None = None,
) -> tuple[
    dict[str, str],
    dict[str, str],
    dict[str, dict[str, dict[str, str]]],
]:
    """Return canonical appliance, target-group, and role-keyed workload identities."""

    if not isinstance(document, dict):
        raise LifecycleError("deployment output must be a JSON object")

    def output_value(name: str) -> Any:
        value = document.get(name)
        if isinstance(value, dict) and "value" in value:
            if set(value) - {"value", "type", "sensitive"}:
                raise LifecycleError(f"deployment output {name} has an invalid Terraform wrapper")
            return value["value"]
        return value

    def exact_site_strings(name: str, pattern: re.Pattern[str]) -> dict[str, str]:
        value = output_value(name)
        if not isinstance(value, dict) or set(value) != set(DEPLOYMENT_SITES):
            raise LifecycleError(f"deployment output {name} must contain exactly west and east")
        result: dict[str, str] = {}
        for site in DEPLOYMENT_SITES:
            candidate = value[site]
            if (
                not isinstance(candidate, str)
                or not pattern.fullmatch(candidate)
                or redact(candidate) != candidate
            ):
                raise LifecycleError(f"deployment output {name}.{site} is invalid")
            result[site] = candidate
        if len(set(result.values())) != len(DEPLOYMENT_SITES):
            raise LifecycleError(f"deployment output {name} contains duplicate identities")
        return result

    instances = exact_site_strings("instance_ids", DEPLOYMENT_INSTANCE_ID_RE)
    target_groups = exact_site_strings("gwlb_target_group_arns", DEPLOYMENT_TARGET_GROUP_ARN_RE)
    workload_value = output_value("workload_instances")
    if not isinstance(workload_value, dict) or set(workload_value) != set(DEPLOYMENT_SITES):
        raise LifecycleError("deployment output workload_instances must contain exactly west and east")
    if expected_sites is not None and (
        not isinstance(expected_sites, dict)
        or set(expected_sites) != set(DEPLOYMENT_SITES)
        or not all(isinstance(expected_sites.get(site), dict) for site in DEPLOYMENT_SITES)
    ):
        raise LifecycleError("expected deployment sites must contain exactly west and east")

    workloads: dict[str, dict[str, dict[str, str]]] = {}
    instance_ids: list[str] = []
    private_ips: list[str] = []
    site_regions: dict[str, str] = {}
    required_fields = set(WORKLOAD_OUTPUT_FIELDS)
    for site in DEPLOYMENT_SITES:
        site_value = workload_value[site]
        if not isinstance(site_value, dict) or set(site_value) not in (
            set(WORKLOAD_ROLES),
            set(WORKLOAD_ROLES) | {"region"},
        ):
            raise LifecycleError(
                f"deployment output workload_instances.{site} must contain exactly initiator and responder"
            )
        declared_site_region = site_value.get("region")
        if declared_site_region is not None and (
            not isinstance(declared_site_region, str) or not DEPLOYMENT_REGION_RE.fullmatch(declared_site_region)
        ):
            raise LifecycleError(f"deployment output workload_instances.{site}.region is invalid")
        expected_site = expected_sites[site] if expected_sites is not None else None
        expected_region = expected_site.get("region") if expected_site is not None else None
        expected_azs = expected_site.get("azs") if expected_site is not None else None
        expected_workload_cidrs = (
            expected_site.get("workload_subnet_cidrs") if expected_site is not None else None
        )
        expected_site_cidrs = expected_site.get("local_site_cidrs") if expected_site is not None else None
        if expected_site is not None and (
            not isinstance(expected_region, str)
            or not DEPLOYMENT_REGION_RE.fullmatch(expected_region)
            or not isinstance(expected_azs, dict)
            or not all(isinstance(key, str) and isinstance(zone, str) for key, zone in expected_azs.items())
            or not isinstance(expected_workload_cidrs, dict)
            or set(expected_workload_cidrs) != set(expected_azs)
            or not all(
                isinstance(key, str) and isinstance(cidr, str)
                for key, cidr in expected_workload_cidrs.items()
            )
            or not isinstance(expected_site_cidrs, list)
            or set(expected_site_cidrs) != set(expected_workload_cidrs.values())
        ):
            raise LifecycleError(f"expected deployment site {site} has invalid workload metadata")

        workloads[site] = {}
        role_regions: list[str] = []
        role_az_keys: list[str] = []
        role_zones: list[str] = []
        for role in WORKLOAD_ROLES:
            role_value = site_value[role]
            if not isinstance(role_value, dict) or set(role_value) not in (
                required_fields,
                required_fields | {"region"},
            ):
                raise LifecycleError(f"deployment output workload_instances.{site}.{role} has an invalid shape")
            if any(not isinstance(role_value[field], str) or not role_value[field] for field in WORKLOAD_OUTPUT_FIELDS):
                raise LifecycleError(f"deployment output workload_instances.{site}.{role} has an invalid field")

            instance_id = role_value["instance_id"]
            private_ip = role_value["private_ip"]
            az_key = role_value["az_key"]
            availability_zone = role_value["availability_zone"]
            subnet_id = role_value["subnet_id"]
            cidr = role_value["cidr"]
            route_table_id = role_value["route_table_id"]
            if not DEPLOYMENT_INSTANCE_ID_RE.fullmatch(instance_id) or redact(instance_id) != instance_id:
                raise LifecycleError(f"deployment output workload_instances.{site}.{role}.instance_id is invalid")
            if not re.fullmatch(r"[a-z][a-z0-9-]{0,15}", az_key):
                raise LifecycleError(f"deployment output workload_instances.{site}.{role}.az_key is invalid")
            zone_match = DEPLOYMENT_AZ_RE.fullmatch(availability_zone)
            if zone_match is None:
                raise LifecycleError(
                    f"deployment output workload_instances.{site}.{role}.availability_zone is invalid"
                )
            derived_region = zone_match.group(1)
            declared_role_region = role_value.get("region")
            if declared_role_region is not None and (
                not isinstance(declared_role_region, str)
                or not DEPLOYMENT_REGION_RE.fullmatch(declared_role_region)
            ):
                raise LifecycleError(f"deployment output workload_instances.{site}.{role}.region is invalid")
            regions = [
                region
                for region in (derived_region, declared_role_region, declared_site_region, expected_region)
                if region is not None
            ]
            if len(set(regions)) != 1:
                raise LifecycleError(
                    f"deployment output workload_instances.{site}.{role} has contradictory region and AZ metadata"
                )
            region = regions[0]
            if expected_azs is not None and expected_azs.get(az_key) != availability_zone:
                raise LifecycleError(
                    f"deployment output workload_instances.{site}.{role} has an unexpected AZ identity"
                )
            if not DEPLOYMENT_SUBNET_ID_RE.fullmatch(subnet_id) or redact(subnet_id) != subnet_id:
                raise LifecycleError(f"deployment output workload_instances.{site}.{role}.subnet_id is invalid")
            if not DEPLOYMENT_ROUTE_TABLE_ID_RE.fullmatch(route_table_id) or redact(route_table_id) != route_table_id:
                raise LifecycleError(
                    f"deployment output workload_instances.{site}.{role}.route_table_id is invalid"
                )
            try:
                address = ipaddress.ip_address(private_ip)
                network = ipaddress.ip_network(cidr, strict=True)
            except ValueError:
                raise LifecycleError(
                    f"deployment output workload_instances.{site}.{role} has invalid IP metadata"
                ) from None
            if address.version != 4 or network.version != 4 or address not in network:
                raise LifecycleError(
                    f"deployment output workload_instances.{site}.{role} has inconsistent IPv4 metadata"
                )
            if expected_site_cidrs is not None and (
                str(network) not in expected_site_cidrs or expected_workload_cidrs.get(az_key) != str(network)
            ):
                raise LifecycleError(
                    f"deployment output workload_instances.{site}.{role} contradicts its configured site CIDR or AZ"
                )

            normalized = {
                "region": region,
                "instance_id": instance_id,
                "private_ip": str(address),
                "az_key": az_key,
                "availability_zone": availability_zone,
                "subnet_id": subnet_id,
                "cidr": str(network),
                "route_table_id": route_table_id,
            }
            workloads[site][role] = normalized
            instance_ids.append(instance_id)
            private_ips.append(str(address))
            role_regions.append(region)
            role_az_keys.append(az_key)
            role_zones.append(availability_zone)

        if len(set(role_regions)) != 1:
            raise LifecycleError(f"deployment output workload_instances.{site} contains multiple regions")
        if len(set(role_az_keys)) != len(WORKLOAD_ROLES) or len(set(role_zones)) != len(WORKLOAD_ROLES):
            raise LifecycleError(f"deployment output workload_instances.{site} contains duplicate role AZs")
        if expected_azs is not None and set(role_az_keys) != set(expected_azs):
            raise LifecycleError(f"deployment output workload_instances.{site} does not cover each configured AZ")
        site_regions[site] = role_regions[0]

    if len(set(site_regions.values())) != len(DEPLOYMENT_SITES):
        raise LifecycleError("deployment workload sites must use distinct regions")
    if len(set(instance_ids)) != len(instance_ids) or set(instance_ids).intersection(instances.values()):
        raise LifecycleError("deployment workload instances must have unique role identities")
    if len(set(private_ips)) != len(private_ips):
        raise LifecycleError("deployment workload instances must have unique private IPs")
    return instances, target_groups, workloads


def wait_deployment(
    config: RunConfig,
    aws: AwsCLI,
    deployment: dict[str, Any],
    *,
    timeout_seconds: int,
    evidence_path: pathlib.Path | None = None,
    sleep: Any = time.sleep,
) -> None:
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
        raise LifecycleError("deployment readiness timeout must be a positive integer")
    instances, target_groups, workloads = deployment_values(deployment, expected_sites=config.sites)
    deadline = time.monotonic() + timeout_seconds
    try:
        for site in DEPLOYMENT_SITES:
            wait_for_instance(
                aws,
                region=config.sites[site]["region"],
                instance_id=instances[site],
                deadline=deadline,
                node_label=f"{site} appliance",
                sleep=sleep,
            )
        for site in DEPLOYMENT_SITES:
            for role in WORKLOAD_ROLES:
                workload = workloads[site][role]
                wait_for_instance(
                    aws,
                    region=workload["region"],
                    instance_id=workload["instance_id"],
                    deadline=deadline,
                    readiness_commands=None,
                    node_label=f"{site} {role} workload",
                    sleep=sleep,
                )
        for site in DEPLOYMENT_SITES:
            wait_for_target(
                aws,
                region=config.sites[site]["region"],
                target_group_arn=target_groups[site],
                deadline=deadline,
                sleep=sleep,
            )
    except Exception as error:
        def collection_failure(diagnostic_error: Exception) -> dict[str, str]:
            return {
                "command_id": "unavailable",
                "status": "collection-failed",
                "stdout": "",
                "stderr": redact(str(diagnostic_error))[:32768],
            }

        diagnostics: dict[str, Any] = {
            "workloads": {site: {} for site in DEPLOYMENT_SITES},
            "target_health": {},
        }
        for site in DEPLOYMENT_SITES:
            try:
                diagnostics[site] = collect_diagnostics(
                    aws,
                    config.sites[site],
                    instances[site],
                    sleep=sleep,
                )
            except Exception as diagnostic_error:
                diagnostics[site] = collection_failure(diagnostic_error)
        for site in DEPLOYMENT_SITES:
            for role in WORKLOAD_ROLES:
                workload = workloads[site][role]
                try:
                    diagnostics["workloads"][site][role] = collect_diagnostics(
                        aws,
                        workload,
                        workload["instance_id"],
                        commands=WORKLOAD_DIAGNOSTIC_COMMANDS,
                        sleep=sleep,
                    )
                except Exception as diagnostic_error:
                    diagnostics["workloads"][site][role] = collection_failure(diagnostic_error)
        for site in DEPLOYMENT_SITES:
            try:
                target_response = aws.json(
                    ["elbv2", "describe-target-health", "--target-group-arn", target_groups[site]],
                    region=config.sites[site]["region"],
                )
                descriptions = target_response.get("TargetHealthDescriptions", [])
                if not isinstance(descriptions, list):
                    descriptions = []
                diagnostics["target_health"][site] = [
                    {
                        key: None if candidate is None else redact(str(candidate))[:2048]
                        for key, candidate in {
                            "target": value.get("Target", {}).get("Id"),
                            "target_state": value.get("TargetHealth", {}).get("State"),
                            "reason": value.get("TargetHealth", {}).get("Reason"),
                            "description": value.get("TargetHealth", {}).get("Description"),
                        }.items()
                    }
                    for value in descriptions
                    if isinstance(value, dict)
                ]
            except Exception as target_error:
                diagnostics["target_health"][site] = {"error": redact(str(target_error))[:2048]}
        if evidence_path is not None:
            evidence_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            evidence_path.write_text(json.dumps(diagnostics, sort_keys=True, separators=(",", ":")) + "\n")
            os.chmod(evidence_path, 0o600)
        diagnostic_ids: dict[str, Any] = {
            site: diagnostics[site]["command_id"] for site in DEPLOYMENT_SITES
        }
        diagnostic_ids["workloads"] = {
            site: {
                role: diagnostics["workloads"][site][role]["command_id"]
                for role in WORKLOAD_ROLES
            }
            for site in DEPLOYMENT_SITES
        }
        failure = redact(str(error))[:4096]
        raise LifecycleError(
            f"deployment readiness failed; redacted diagnostics={evidence_path}; "
            f"command ids={json.dumps(diagnostic_ids, sort_keys=True)}: {failure}"
        ) from None


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
            candidate = {
                "arn": arn,
                "region": effective_region,
                "run_id": config.run_id,
                "expires_at": config.expires_at,
            }
            if arn in tagged and tagged[arn] != candidate:
                raise LifecycleError("tag audit returned one resource under conflicting regional identities")
            tagged[arn] = candidate
    return [tagged[arn] for arn in sorted(tagged) if owned_resource_is_live(aws, tagged[arn])]


def owned_resource_kind(arn: str) -> tuple[str, str]:
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn":
        raise LifecycleError(f"owned residual has an invalid ARN: {arn}")
    partition, service, region, account, resource = parts[1], parts[2], parts[3], parts[4], parts[5]
    regional_identity_valid = (
        re.fullmatch(r"aws(?:-[a-z0-9-]+)?", partition) is not None
        and DEPLOYMENT_REGION_RE.fullmatch(region) is not None
        and re.fullmatch(r"[0-9]{12}", account) is not None
    )
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
        if kind == "network-acl":
            if regional_identity_valid and re.fullmatch(r"acl-[A-Za-z0-9-]{1,127}", identifier):
                return "network-acl", identifier
            raise LifecycleError(f"owned residual has an invalid network ACL ARN: {arn}")
        if kind == "vpc-flow-log":
            if regional_identity_valid and re.fullmatch(r"fl-[A-Za-z0-9-]{1,127}", identifier):
                return "flow-log", identifier
            raise LifecycleError(f"owned residual has an invalid Flow Log ARN: {arn}")
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
    if service == "logs" and resource.startswith("log-group:"):
        identifier = resource.removeprefix("log-group:")
        if identifier.endswith(":*"):
            identifier = identifier[:-2]
        if (
            regional_identity_valid
            and re.fullmatch(r"[.\-_/#A-Za-z0-9]{1,512}", identifier)
            and "*" not in identifier
        ):
            return "log-group", identifier
        raise LifecycleError(f"owned residual has an invalid CloudWatch log group ARN: {arn}")
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
    "network-acl": ("InvalidNetworkAclID.NotFound", "InvalidNetworkAclId.NotFound"),
    "flow-log": ("InvalidFlowLogId.NotFound",),
    "log-group": ("ResourceNotFoundException",),
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


OWNERSHIP_VERIFIED_RESOURCE_KINDS = {"network-acl", "flow-log", "log-group"}


def validate_residual_region(resource: dict[str, str]) -> None:
    arn_region = resource["arn"].split(":", 5)[3]
    if arn_region != resource["region"]:
        raise LifecycleError("owned regional residual ARN differs from its audit region")


def expected_residual_ownership(resource: dict[str, str]) -> tuple[str, str]:
    run_id, expires_at = resource.get("run_id"), resource.get("expires_at")
    if not isinstance(run_id, str) or not run_id or not isinstance(expires_at, str) or not expires_at:
        raise LifecycleError("owned residual lacks its exact run/TTL identity")
    return run_id, expires_at


def validate_owned_tag_list(tags_value: Any, resource: dict[str, str], context: str) -> None:
    if not isinstance(tags_value, list) or not all(
        isinstance(tag, dict) and isinstance(tag.get("Key"), str) and isinstance(tag.get("Value"), str)
        for tag in tags_value
    ):
        raise LifecycleError(f"authoritative {context} response has an invalid tag schema")
    tags: dict[str, str] = {}
    for tag in tags_value:
        key, value = str(tag["Key"]), str(tag["Value"])
        if key in tags:
            raise LifecycleError(f"authoritative {context} response contains a duplicate tag key")
        tags[key] = value
    run_id, expires_at = expected_residual_ownership(resource)
    if tags.get("EnvelopeRun") != run_id or tags.get("ExpiresAt") != expires_at:
        raise LifecycleError(f"authoritative {context} response differs from the exact run/TTL identity")


def validate_owned_tag_map(tags_value: Any, resource: dict[str, str], context: str) -> None:
    if not isinstance(tags_value, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in tags_value.items()
    ):
        raise LifecycleError(f"authoritative {context} response has an invalid tag schema")
    run_id, expires_at = expected_residual_ownership(resource)
    if tags_value.get("EnvelopeRun") != run_id or tags_value.get("ExpiresAt") != expires_at:
        raise LifecycleError(f"authoritative {context} response differs from the exact run/TTL identity")


def describe_owned_network_acl(
    aws: AwsCLI, resource: dict[str, str], identifier: str
) -> dict[str, Any] | None:
    validate_residual_region(resource)
    response = aws.json(["ec2", "describe-network-acls", "--network-acl-ids", identifier], region=resource["region"])
    acl = exact_described_item(response, "NetworkAcls", "NetworkAclId", identifier)
    if acl is None:
        return None
    if acl.get("IsDefault") is not False:
        raise LifecycleError("owned cleanup refuses a default or ambiguously classified network ACL")
    vpc_id = acl.get("VpcId")
    if not isinstance(vpc_id, str) or not re.fullmatch(r"vpc-[A-Za-z0-9-]{1,127}", vpc_id):
        raise LifecycleError("authoritative network ACL response omitted its exact VPC identity")
    validate_owned_tag_list(acl.get("Tags"), resource, "network ACL")
    associations = acl.get("Associations")
    if not isinstance(associations, list) or not all(isinstance(value, dict) for value in associations):
        raise LifecycleError("authoritative network ACL response has an invalid association schema")
    for association in associations:
        if (
            association.get("NetworkAclId") != identifier
            or not isinstance(association.get("NetworkAclAssociationId"), str)
            or not re.fullmatch(r"aclassoc-[A-Za-z0-9-]{1,127}", association["NetworkAclAssociationId"])
            or not isinstance(association.get("SubnetId"), str)
            or not re.fullmatch(r"subnet-[A-Za-z0-9-]{1,127}", association["SubnetId"])
        ):
            raise LifecycleError("authoritative network ACL response contains a conflicting association identity")
    return acl


def describe_owned_flow_log(
    aws: AwsCLI, resource: dict[str, str], identifier: str
) -> dict[str, Any] | None:
    validate_residual_region(resource)
    response = aws.json(["ec2", "describe-flow-logs", "--flow-log-ids", identifier], region=resource["region"])
    flow_log = exact_described_item(response, "FlowLogs", "FlowLogId", identifier)
    if flow_log is None:
        return None
    status = flow_log.get("FlowLogStatus")
    if not isinstance(status, str):
        raise LifecycleError("authoritative Flow Log response omitted its status")
    normalized_status = status.upper()
    if normalized_status not in {"ACTIVE", "DELETING", "DELETED", "FAILED"}:
        raise LifecycleError("authoritative Flow Log response has an invalid status")
    validate_owned_tag_list(flow_log.get("Tags"), resource, "Flow Log")
    return None if normalized_status == "DELETED" else flow_log


def canonical_log_group_arn(arn: str, identifier: str) -> str:
    parts = arn.split(":", 5)
    return ":".join(parts[:5]) + f":log-group:{identifier}"


def describe_owned_log_group(
    aws: AwsCLI, resource: dict[str, str], identifier: str
) -> dict[str, Any] | None:
    validate_residual_region(resource)
    canonical_arn = canonical_log_group_arn(resource["arn"], identifier)
    tags = aws.json(
        ["logs", "list-tags-for-resource", "--resource-arn", canonical_arn],
        region=resource["region"],
    )
    validate_owned_tag_map(tags.get("tags"), resource, "log group tags")
    return {"logGroupName": identifier, "logGroupArn": canonical_arn}


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
        if kind == "network-acl":
            return describe_owned_network_acl(aws, resource, identifier) is not None
        if kind == "flow-log":
            return describe_owned_flow_log(aws, resource, identifier) is not None
        if kind == "log-group":
            return describe_owned_log_group(aws, resource, identifier) is not None
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
    elif kind == "network-acl":
        acl = describe_owned_network_acl(aws, resource, identifier)
        if acl is None:
            return
        associations = acl["Associations"]
        if associations:
            vpc_id = str(acl["VpcId"])
            default_response = aws.json(
                [
                    "ec2",
                    "describe-network-acls",
                    "--filters",
                    f"Name=vpc-id,Values={vpc_id}",
                    "Name=default,Values=true",
                ],
                region=region,
            )
            defaults = default_response.get("NetworkAcls")
            if not isinstance(defaults, list) or not all(isinstance(value, dict) for value in defaults):
                raise LifecycleError("authoritative default network ACL response has an invalid schema")
            if len(defaults) != 1:
                raise LifecycleError("network ACL association restoration did not find exactly one VPC default ACL")
            default_acl = defaults[0]
            default_id = default_acl.get("NetworkAclId")
            if (
                default_acl.get("IsDefault") is not True
                or default_acl.get("VpcId") != vpc_id
                or not isinstance(default_id, str)
                or default_id == identifier
                or not re.fullmatch(r"acl-[A-Za-z0-9-]{1,127}", default_id)
            ):
                raise LifecycleError("network ACL association restoration found a conflicting default ACL identity")
            for association in associations:
                association_id = str(association["NetworkAclAssociationId"])
                replaced = aws.json(
                    [
                        "ec2",
                        "replace-network-acl-association",
                        "--association-id",
                        association_id,
                        "--network-acl-id",
                        default_id,
                    ],
                    region=region,
                )
                new_association_id = replaced.get("NewAssociationId")
                if (
                    not isinstance(new_association_id, str)
                    or new_association_id == association_id
                    or not re.fullmatch(r"aclassoc-[A-Za-z0-9-]{1,127}", new_association_id)
                ):
                    raise LifecycleError("network ACL association restoration returned an invalid identity")
        aws.json(["ec2", "delete-network-acl", "--network-acl-id", identifier], region=region)
    elif kind == "flow-log":
        if describe_owned_flow_log(aws, resource, identifier) is None:
            return
        response = aws.json(["ec2", "delete-flow-logs", "--flow-log-ids", identifier], region=region)
        unsuccessful = response.get("Unsuccessful")
        if not isinstance(unsuccessful, list) or not all(isinstance(value, dict) for value in unsuccessful):
            raise LifecycleError("Flow Log deletion returned an invalid unsuccessful-item schema")
        if unsuccessful:
            error_codes: list[str] = []
            for item in unsuccessful:
                error = item.get("Error")
                resource_id = item.get("ResourceId")
                if (
                    not isinstance(error, dict)
                    or not isinstance(error.get("Code"), str)
                    or resource_id != identifier
                ):
                    raise LifecycleError("Flow Log deletion returned a conflicting unsuccessful-item identity")
                error_codes.append(str(error["Code"]))
            if all(
                any(marker in code for marker in OWNED_RESOURCE_ABSENT_MARKERS["flow-log"])
                for code in error_codes
            ):
                return
            raise LifecycleError("Flow Log deletion reported an unsuccessful exact ID")
    elif kind == "log-group":
        if describe_owned_log_group(aws, resource, identifier) is None:
            return
        aws.json(["logs", "delete-log-group", "--log-group-name", identifier], region=region)
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
    "flow-log": 5,
    "vpc-endpoint": 10,
    "log-group": 15,
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
    "network-acl": 125,
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
    partition = str(config.backend["kms_key_arn"]).split(":", 2)[1]
    backend_arn = f"arn:{partition}:s3:::{config.backend['bucket']}"
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
                kind, _ = owned_resource_kind(arn)
                if kind in OWNERSHIP_VERIFIED_RESOURCE_KINDS and (
                    resource.get("run_id") != config.run_id or resource.get("expires_at") != config.expires_at
                ):
                    raise LifecycleError("owned cleanup residual has a conflicting run/TTL identity")
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
    retry_errors: dict[str, str] = {}
    observed = list(resources)
    deadline = monotonic() + RESIDUAL_CLEANUP_TIMEOUT_SECONDS
    backoff = RESIDUAL_CLEANUP_INITIAL_BACKOFF_SECONDS
    while pending:
        for resource in sorted(pending, key=owned_resource_delete_priority):
            arn = resource["arn"]
            kind, _ = owned_resource_kind(arn)
            try:
                delete_owned_resource(aws, resource)
            except CommandError as error:
                if any(marker in error.raw_stderr for marker in OWNED_RESOURCE_ABSENT_MARKERS[kind]):
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
    with _CONCURRENT_PREPARE_RUNS_GUARD:
        rejected_prepare_claim = run_dir in _CONCURRENT_PREPARE_RUNS
    if rejected_prepare_claim and not janitor:
        raise ConcurrentLifecycleError("cleanup is not authorized after a rejected durable prepare claim")
    store = ManifestStore(config, aws, run_dir)
    manifest = store.recover() if recover or not dry_run else store.load_local()
    if manifest.get("phase") == "e2e_running":
        expiry = dt.datetime.fromisoformat(config.expires_at.replace("Z", "+00:00"))
        if not (janitor and recover and expiry <= dt.datetime.now(dt.timezone.utc)):
            raise LifecycleError(
                "cleanup refuses an active E2E claim; only expired-TTL janitor recovery may clean an orphan"
            )
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
        manifest.pop("apply_claimed_at", None)
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
            deployment_text = args.deployment_file.expanduser().resolve().read_text()
        except OSError as error:
            raise LifecycleError(f"cannot read deployment output JSON: {error}") from error
        deployment = parse_deployment_json(deployment_text)
        wait_and_record(
            config,
            aws,
            tailscale,
            run_dir,
            deployment,
            timeout_seconds=args.timeout_seconds,
        )
        print("both appliances, all four workloads, and both GWLB targets are ready")
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
