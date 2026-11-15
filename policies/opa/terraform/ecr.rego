# ECR: immutable tags (deploy by digest/tag safely) and scan on push.
package terraform.ecr

import data.terraform.lib
import rego.v1

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_ecr_repository"
	object.get(rc.change.after, "image_tag_mutability", "MUTABLE") != "IMMUTABLE"
	msg := sprintf("%s must set image_tag_mutability = \"IMMUTABLE\"", [rc.address])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_ecr_repository"
	object.get(lib.block(rc.change.after, "image_scanning_configuration"), "scan_on_push", false) != true
	msg := sprintf("%s must enable image_scanning_configuration.scan_on_push (or registry-level enhanced scanning)", [rc.address])
}

warn contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_ecr_repository"
	not any_lifecycle_policy
	msg := sprintf("%s has no aws_ecr_lifecycle_policy in this plan: old images will accumulate", [rc.address])
}

any_lifecycle_policy if {
	some rc in input.resource_changes
	rc.type == "aws_ecr_lifecycle_policy"
}
