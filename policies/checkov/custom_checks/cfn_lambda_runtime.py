"""CKV_ORG_11: CloudFormation / SAM Lambda functions must not use deprecated runtimes."""
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult

DEPRECATED_PREFIXES = ("python2", "python3.6", "python3.7", "python3.8", "nodejs1", "nodejs8", "nodejs10",
                       "nodejs12", "nodejs14", "nodejs16", "java8", "go1.x", "ruby2", "dotnetcore", "dotnet6")


class CfnLambdaRuntime(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Ensure CloudFormation Lambda functions use a supported runtime",
            id="CKV_ORG_11",
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=["AWS::Lambda::Function", "AWS::Serverless::Function"],
        )

    def scan_resource_conf(self, conf: dict) -> CheckResult:
        runtime = (conf.get("Properties") or {}).get("Runtime")
        if runtime is None:
            return CheckResult.PASSED  # image-based function or Globals-defined runtime
        if not isinstance(runtime, str):
            return CheckResult.UNKNOWN
        return CheckResult.FAILED if runtime.startswith(DEPRECATED_PREFIXES) else CheckResult.PASSED


check = CfnLambdaRuntime()
