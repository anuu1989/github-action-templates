package terraform.ecr_test

import data.terraform.ecr
import rego.v1

repo(after) := {"resource_changes": [{"address": "aws_ecr_repository.app", "type": "aws_ecr_repository", "change": {"actions": ["create"], "after": after}}]}

test_mutable_unscanned_denied if {
	count(ecr.deny) == 2 with input as repo({"image_tag_mutability": "MUTABLE", "image_scanning_configuration": [{"scan_on_push": false}]})
}

test_compliant_repo_allowed if {
	count(ecr.deny) == 0 with input as repo({"image_tag_mutability": "IMMUTABLE", "image_scanning_configuration": [{"scan_on_push": true}]})
}

test_missing_lifecycle_warns if {
	count(ecr.warn) == 1 with input as repo({"image_tag_mutability": "IMMUTABLE"})
}
