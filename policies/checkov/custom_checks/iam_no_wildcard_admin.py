"""CKV_ORG_3: IAM policies must not grant '*' (or sensitive '<svc>:*') on all resources."""
import json

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

SENSITIVE_SERVICES = {"iam", "sts", "kms", "organizations", "secretsmanager"}


def _as_list(value):
    return value if isinstance(value, list) else [value]


class IAMNoWildcardAdmin(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Ensure IAM policies do not grant wildcard admin or sensitive service wildcards on all resources",
            id="CKV_ORG_3",
            categories=[CheckCategories.IAM],
            supported_resources=["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"],
        )

    def scan_resource_conf(self, conf: dict) -> CheckResult:
        policy = conf.get("policy", [None])[0]
        if isinstance(policy, str):
            if policy.startswith("${"):  # unresolved reference, e.g. data.aws_iam_policy_document.x.json
                return CheckResult.UNKNOWN
            try:
                policy = json.loads(policy)
            except ValueError:
                return CheckResult.UNKNOWN
        if not isinstance(policy, dict):
            return CheckResult.UNKNOWN

        for statement in _as_list(policy.get("Statement", [])):
            if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
                continue
            if "*" not in _as_list(statement.get("Resource", [])):
                continue
            for action in _as_list(statement.get("Action", [])):
                if action == "*":
                    return CheckResult.FAILED
                service, _, verb = str(action).lower().partition(":")
                if verb == "*" and service in SENSITIVE_SERVICES:
                    return CheckResult.FAILED
        return CheckResult.PASSED


check = IAMNoWildcardAdmin()
