"""CKV_ORG_5: ECR repositories must use immutable tags and scan on push."""
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _first(value, default=None):
    while isinstance(value, list):
        if not value:
            return default
        value = value[0]
    return default if value is None else value


class ECRImmutableAndScanned(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Ensure ECR repositories have immutable tags and scan on push",
            id="CKV_ORG_5",
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=["aws_ecr_repository"],
        )

    def scan_resource_conf(self, conf: dict) -> CheckResult:
        self.evaluated_keys = ["image_tag_mutability", "image_scanning_configuration/[0]/scan_on_push"]
        immutable = _first(conf.get("image_tag_mutability")) == "IMMUTABLE"
        scanning = _first(conf.get("image_scanning_configuration"), {})
        scan_on_push = _first(scanning.get("scan_on_push"), False) is True
        return CheckResult.PASSED if immutable and scan_on_push else CheckResult.FAILED


check = ECRImmutableAndScanned()
