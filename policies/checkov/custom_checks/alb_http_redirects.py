"""CKV_ORG_4: HTTP load balancer listeners must only redirect to HTTPS."""
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _first(value, default=None):
    while isinstance(value, list):
        if not value:
            return default
        value = value[0]
    return default if value is None else value


class ALBHttpRedirects(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Ensure HTTP load balancer listeners redirect to HTTPS",
            id="CKV_ORG_4",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["aws_lb_listener", "aws_alb_listener"],
        )

    def scan_resource_conf(self, conf: dict) -> CheckResult:
        if _first(conf.get("protocol")) != "HTTP":
            return CheckResult.PASSED
        action = _first(conf.get("default_action"), {})
        return CheckResult.PASSED if _first(action.get("type")) == "redirect" else CheckResult.FAILED


check = ALBHttpRedirects()
