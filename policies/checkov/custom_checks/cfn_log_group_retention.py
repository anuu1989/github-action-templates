"""CKV_ORG_10: CloudFormation AWS::Logs::LogGroup must set RetentionInDays >= 30."""
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult


class CfnLogGroupRetention(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Ensure CloudFormation log groups set RetentionInDays >= 30",
            id="CKV_ORG_10",
            categories=[CheckCategories.LOGGING],
            supported_resources=["AWS::Logs::LogGroup"],
        )

    def scan_resource_conf(self, conf: dict) -> CheckResult:
        days = (conf.get("Properties") or {}).get("RetentionInDays")
        if isinstance(days, dict):  # Ref / Fn::If etc.
            return CheckResult.UNKNOWN
        try:
            return CheckResult.PASSED if int(days) >= 30 else CheckResult.FAILED
        except (TypeError, ValueError):
            return CheckResult.FAILED


check = CfnLogGroupRetention()
