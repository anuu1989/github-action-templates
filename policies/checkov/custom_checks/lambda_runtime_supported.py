"""CKV_ORG_2: Lambda functions must not use deprecated / soon-to-be-deprecated runtimes."""
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

DEPRECATED_PREFIXES = ("python3.7", "python3.8", "nodejs12", "nodejs14", "nodejs16", "java8", "go1.x", "ruby2", "dotnetcore", "dotnet6")


class LambdaRuntimeSupported(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Ensure Lambda functions use a supported runtime",
            id="CKV_ORG_2",
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=["aws_lambda_function"],
        )

    def scan_resource_conf(self, conf: dict) -> CheckResult:
        runtime = conf.get("runtime", [None])[0]
        if runtime is None:  # container image functions have no runtime
            return CheckResult.PASSED
        if not isinstance(runtime, str) or runtime.startswith("${"):
            return CheckResult.UNKNOWN
        return CheckResult.FAILED if runtime.startswith(DEPRECATED_PREFIXES) else CheckResult.PASSED


check = LambdaRuntimeSupported()
