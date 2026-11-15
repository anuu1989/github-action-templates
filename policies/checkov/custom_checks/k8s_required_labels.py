"""CKV_ORG_7: Kubernetes workloads, Services and Ingresses must carry ownership labels."""
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.checks.resource.base_spec_check import BaseK8Check

REQUIRED_LABELS = {"app.kubernetes.io/name", "team"}


class K8sRequiredLabels(BaseK8Check):
    def __init__(self) -> None:
        super().__init__(
            name=f"Ensure Kubernetes resources have labels {sorted(REQUIRED_LABELS)}",
            id="CKV_ORG_7",
            categories=[CheckCategories.KUBERNETES],
            supported_entities=["Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job", "Service", "Ingress"],
        )

    def scan_spec_conf(self, conf: dict) -> CheckResult:
        labels = (conf.get("metadata") or {}).get("labels") or {}
        return CheckResult.PASSED if REQUIRED_LABELS <= set(labels) else CheckResult.FAILED


check = K8sRequiredLabels()
