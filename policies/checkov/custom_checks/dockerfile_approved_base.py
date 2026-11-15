"""CKV_ORG_9: Dockerfile base images must come from approved registries (stage aliases & scratch allowed)."""
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.dockerfile.base_dockerfile_check import BaseDockerfileCheck

APPROVED_PREFIXES = ("public.ecr.aws/", "ghcr.io/acme/", "cgr.dev/chainguard/")


class DockerfileApprovedBase(BaseDockerfileCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Ensure Dockerfile base images come from approved registries",
            id="CKV_ORG_9",
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_instructions=("FROM",),
        )

    def scan_resource_conf(self, conf):
        stages = set()  # earlier `FROM x AS name` aliases may be reused as a base
        for instruction in conf:
            tokens = [t for t in instruction["value"].split() if not t.startswith("--")]
            if not tokens:
                continue
            image = tokens[0]
            if image != "scratch" and image.lower() not in stages and not image.startswith(APPROVED_PREFIXES):
                return CheckResult.FAILED, [instruction]
            if len(tokens) == 3 and tokens[1].lower() == "as":
                stages.add(tokens[2].lower())
        return CheckResult.PASSED, None


check = DockerfileApprovedBase()
