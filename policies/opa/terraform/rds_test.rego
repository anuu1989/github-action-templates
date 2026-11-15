package terraform.rds_test

import data.terraform.rds
import rego.v1

rc(type, after, unknown) := {"resource_changes": [{
	"address": sprintf("%s.db", [type]),
	"type": type,
	"change": {"actions": ["create"], "after": after, "after_unknown": unknown},
}]}

test_unencrypted_public_db_denied if {
	count(rds.deny) == 2 with input as rc("aws_db_instance", {"storage_encrypted": false, "publicly_accessible": true}, {})
}

test_compliant_db_allowed if {
	count(rds.deny) == 0 with input as rc("aws_db_instance", {"storage_encrypted": true, "publicly_accessible": false, "deletion_protection": true}, {})
}

test_unknown_encryption_not_denied if {
	count(rds.deny) == 0 with input as rc("aws_rds_cluster", {}, {"storage_encrypted": true})
}

test_missing_deletion_protection_warns if {
	count(rds.warn) == 1 with input as rc("aws_rds_cluster", {"storage_encrypted": true}, {})
}
