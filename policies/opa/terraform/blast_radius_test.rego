package terraform.blast_radius_test

import data.terraform.blast_radius
import rego.v1

plan(n, actions) := {"resource_changes": [rc |
	some i in numbers.range(1, n)
	rc := {"address": sprintf("aws_s3_object.o[%d]", [i]), "type": "aws_s3_object", "change": {"actions": actions}}
]}

test_many_deletes_denied if {
	count(blast_radius.deny_too_many_deletes) == 1 with input as plan(6, ["delete"])
}

test_few_deletes_allowed if {
	count(blast_radius.deny_too_many_deletes) == 0 with input as plan(5, ["delete"])
}

test_large_change_warns if {
	count(blast_radius.warn) == 1 with input as plan(51, ["create"])
}

test_noops_not_counted if {
	count(blast_radius.warn) == 0 with input as plan(100, ["no-op"])
}

test_limits_overridable if {
	count(blast_radius.deny_too_many_deletes) == 0 with input as plan(6, ["delete"]) with data.blast_radius as {"max_deletes": 10}
}
