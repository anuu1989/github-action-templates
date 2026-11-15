package terraform.encryption_test

import data.terraform.encryption
import rego.v1

plan(type, after) := {"resource_changes": [{
	"address": sprintf("%s.this", [type]),
	"type": type,
	"change": {"actions": ["create"], "after": after, "after_unknown": {}},
}]}

test_unencrypted_ebs_denied if {
	count(encryption.deny) == 1 with input as plan("aws_ebs_volume", {"encrypted": false})
}

test_encrypted_efs_allowed if {
	count(encryption.deny) == 0 with input as plan("aws_efs_file_system", {"encrypted": true})
}

test_elasticache_requires_both if {
	count(encryption.deny) == 2 with input as plan("aws_elasticache_replication_group", {})
}

test_instance_unencrypted_root_denied if {
	count(encryption.deny) == 1 with input as plan("aws_instance", {"root_block_device": [{"encrypted": false}], "ebs_block_device": []})
}

test_sqs_with_kms_allowed if {
	count(encryption.deny) == 0 with input as plan("aws_sqs_queue", {"sqs_managed_sse_enabled": false, "kms_master_key_id": "alias/sqs"})
}

test_sqs_without_sse_denied if {
	count(encryption.deny) == 1 with input as plan("aws_sqs_queue", {"sqs_managed_sse_enabled": false, "kms_master_key_id": null})
}

test_log_group_without_cmk_warns if {
	count(encryption.warn) == 1 with input as plan("aws_cloudwatch_log_group", {"kms_key_id": null})
}
