# S3 buckets must never be public.
package terraform.s3

import data.terraform.lib
import rego.v1

public_acls := {"public-read", "public-read-write", "authenticated-read"}

block_flags := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_s3_bucket_acl"
	rc.change.after.acl in public_acls
	msg := sprintf("%s uses public ACL '%s'", [rc.address, rc.change.after.acl])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type in {"aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block"}
	some flag in block_flags
	object.get(rc.change.after, flag, false) != true
	msg := sprintf("%s must set %s = true", [rc.address, flag])
}

warn contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_s3_bucket_versioning"
	some cfg in lib.as_array(rc.change.after.versioning_configuration)
	cfg.status != "Enabled"
	msg := sprintf("%s: versioning is not Enabled", [rc.address])
}
