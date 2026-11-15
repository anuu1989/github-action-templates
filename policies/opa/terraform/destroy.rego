# Surface every destroy, and block destroying stateful resources unless explicitly excepted.
# To allow a planned deletion, add a conftest exception (see README) or use a dedicated pipeline.
package terraform.destroy

import data.terraform.lib
import rego.v1

protected_types := {
	"aws_db_instance", "aws_rds_cluster", "aws_dynamodb_table",
	"aws_s3_bucket", "aws_kms_key", "aws_efs_file_system", "aws_elasticache_replication_group",
}

warn contains msg if {
	some rc in lib.resources_deleting
	msg := sprintf("%s will be destroyed (actions: %v)", [rc.address, rc.change.actions])
}

deny_protected_destroy contains msg if {
	some rc in lib.resources_deleting
	rc.type in protected_types
	msg := sprintf("%s is a protected stateful resource and would be destroyed/replaced", [rc.address])
}

# Escape hatch: `terraform plan -var allow_destroy=true` (declare `variable "allow_destroy"` in the root module)
# turns the protected-destroy deny off for that run. Conftest reads `exception` rules natively.
exception contains rules if {
	input.variables.allow_destroy.value == true
	rules := ["protected_destroy"]
}
