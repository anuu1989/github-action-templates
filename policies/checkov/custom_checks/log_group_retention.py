"""CKV_ORG_6: CloudWatch log groups must set a retention between 30 days and 10 years."""
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

MIN_DAYS, MAX_DAYS = 30, 3653


class LogGroupRetention(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name=f"Ensure CloudWatch log groups retain logs between {MIN_DAYS} and {MAX_DAYS} days",
            id="CKV_ORG_6",
            categories=[CheckCategories.LOGGING],
            supported_resources=["aws_cloudwatch_log_group"],
        )

    def scan_resource_conf(self, conf: dict) -> CheckResult:
        self.evaluated_keys = ["retention_in_days"]
        days = conf.get("retention_in_days", [0])[0]
        if isinstance(days, str):
            if days.startswith("${"):
                return CheckResult.UNKNOWN
            days = int(days) if days.isdigit() else 0
        return CheckResult.PASSED if MIN_DAYS <= (days or 0) <= MAX_DAYS else CheckResult.FAILED


check = LogGroupRetention()
