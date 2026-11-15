package terraform.destroy_test

import data.terraform.destroy
import rego.v1

rc(type, actions) := {"resource_changes": [{
	"address": sprintf("%s.this", [type]),
	"type": type,
	"change": {"actions": actions},
}]}

test_replace_database_denied if {
	count(destroy.deny_protected_destroy) == 1 with input as rc("aws_db_instance", ["delete", "create"])
}

test_delete_stateless_only_warns if {
	count(destroy.deny_protected_destroy) == 0 with input as rc("aws_iam_role", ["delete"])
	count(destroy.warn) == 1 with input as rc("aws_iam_role", ["delete"])
}

test_create_no_findings if {
	count(destroy.warn) == 0 with input as rc("aws_s3_bucket", ["create"])
}

test_exception_when_allow_destroy if {
	inp := object.union(rc("aws_db_instance", ["delete"]), {"variables": {"allow_destroy": {"value": true}}})
	count(destroy.exception) == 1 with input as inp
}
