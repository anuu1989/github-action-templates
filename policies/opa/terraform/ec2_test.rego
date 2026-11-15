package terraform.ec2_test

import data.terraform.ec2
import rego.v1

instance(itype, tokens) := {"resource_changes": [{
	"address": "aws_instance.web",
	"type": "aws_instance",
	"change": {"actions": ["create"], "after": {
		"instance_type": itype,
		"metadata_options": [{"http_tokens": tokens}],
	}},
}]}

test_approved_type_with_imdsv2_allowed if {
	count(ec2.deny) == 0 with input as instance("t3.micro", "required")
}

test_unapproved_family_denied if {
	count(ec2.deny) == 1 with input as instance("p4d.24xlarge", "required")
}

test_imdsv1_denied if {
	count(ec2.deny) == 1 with input as instance("m7g.large", "optional")
}

test_custom_allowed_families_from_data if {
	count(ec2.deny) == 0 with input as instance("p4d.24xlarge", "required")
		with data.allowed_instance_families as ["p4d"]
}
