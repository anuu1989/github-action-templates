"""CKV_ORG_8: Container images must come from approved registries (any private ECR is allowed)."""
from __future__ import annotations

import re
from typing import Any

from checkov.common.models.enums import CheckResult
from checkov.kubernetes.checks.resource.base_container_check import BaseK8sContainerCheck

APPROVED_PREFIXES = ("ghcr.io/acme/", "public.ecr.aws/acme/", "registry.k8s.io/")
ECR = re.compile(r"^\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/")


class K8sApprovedRegistries(BaseK8sContainerCheck):
    def __init__(self) -> None:
        # Evaluated for every container & initContainer of every workload kind.
        super().__init__(name="Ensure container images come from approved registries", id="CKV_ORG_8")

    def scan_container_conf(self, metadata: dict[str, Any], conf: dict[str, Any]) -> CheckResult:
        image = conf.get("image")
        if not isinstance(image, str):
            return CheckResult.UNKNOWN
        if image.startswith(APPROVED_PREFIXES) or ECR.match(image):
            return CheckResult.PASSED
        return CheckResult.FAILED


check = K8sApprovedRegistries()
