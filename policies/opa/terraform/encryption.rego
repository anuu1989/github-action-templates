# Encryption at rest / in transit for common storage & messaging services.
package terraform.encryption

import data.terraform.lib
import rego.v1

# resource type -> attribute that must be true
must_be_true := {
	"aws_ebs_volume": "encrypted",
	"aws_efs_file_system": "encrypted",
	"aws_ebs_encryption_by_default": "enabled",
	"aws_elasticache_replication_group": "at_rest_encryption_enabled",
	"aws_redshift_cluster": "encrypted",
	"aws_docdb_cluster": "storage_encrypted",
	"aws_neptune_cluster": "storage_encrypted",
}

deny contains msg if {
	some rc in lib.resources_changing
	attr := must_be_true[rc.type]
	not lib.unknown(rc, attr)
	object.get(rc.change.after, attr, false) != true
	msg := sprintf("%s must set %s = true", [rc.address, attr])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_elasticache_replication_group"
	object.get(rc.change.after, "transit_encryption_enabled", false) != true
	msg := sprintf("%s must set transit_encryption_enabled = true", [rc.address])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_instance"
	some device_type in ["root_block_device", "ebs_block_device"]
	some device in lib.as_array(object.get(rc.change.after, device_type, []))
	object.get(device, "encrypted", false) != true
	msg := sprintf("%s: %s must be encrypted", [rc.address, device_type])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_sqs_queue"
	not lib.unknown(rc, "sqs_managed_sse_enabled")
	object.get(rc.change.after, "sqs_managed_sse_enabled", false) != true
	object.get(rc.change.after, "kms_master_key_id", null) in {null, ""}
	msg := sprintf("%s must enable SSE (sqs_managed_sse_enabled or kms_master_key_id)", [rc.address])
}

warn contains msg if {
	some rc in lib.resources_changing
	rc.type in {"aws_sns_topic", "aws_cloudwatch_log_group"}
	attr := {"aws_sns_topic": "kms_master_key_id", "aws_cloudwatch_log_group": "kms_key_id"}[rc.type]
	object.get(rc.change.after, attr, null) in {null, ""}
	msg := sprintf("%s should be encrypted with a customer-managed KMS key (%s)", [rc.address, attr])
}
