package terraform.s3_test

import data.terraform.s3
import rego.v1

rc(type, after) := {"resource_changes": [{
	"address": sprintf("%s.this", [type]),
	"type": type,
	"change": {"actions": ["create"], "after": after},
}]}

test_public_acl_denied if {
	count(s3.deny) == 1 with input as rc("aws_s3_bucket_acl", {"acl": "public-read"})
}

test_private_acl_allowed if {
	count(s3.deny) == 0 with input as rc("aws_s3_bucket_acl", {"acl": "private"})
}

test_partial_public_access_block_denied if {
	count(s3.deny) == 2 with input as rc("aws_s3_bucket_public_access_block", {
		"block_public_acls": true, "block_public_policy": false,
		"ignore_public_acls": true,
	})
}

test_full_public_access_block_allowed if {
	count(s3.deny) == 0 with input as rc("aws_s3_bucket_public_access_block", {
		"block_public_acls": true, "block_public_policy": true,
		"ignore_public_acls": true, "restrict_public_buckets": true,
	})
}

test_versioning_suspended_warns if {
	count(s3.warn) == 1 with input as rc("aws_s3_bucket_versioning", {"versioning_configuration": [{"status": "Suspended"}]})
}
