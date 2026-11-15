"""CKV_ORG_1: EC2 instances must use an approved instance family."""
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

APPROVED_FAMILIES = {"t3", "t3a", "t4g", "m6i", "m7i", "m7g", "c7i", "c7g", "r7i", "r7g"}


class EC2ApprovedInstanceTypes(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Ensure EC2 instances use an approved instance family",
            id="CKV_ORG_1",
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=["aws_instance"],
        )

    def scan_resource_conf(self, conf: dict) -> CheckResult:
        instance_type = conf.get("instance_type", [None])[0]
        # Variables that couldn't be resolved are left as strings like "${var.x}": don't fail those.
        if not isinstance(instance_type, str) or instance_type.startswith("${"):
            return CheckResult.UNKNOWN
        family = instance_type.split(".")[0]
        return CheckResult.PASSED if family in APPROVED_FAMILIES else CheckResult.FAILED


check = EC2ApprovedInstanceTypes()
