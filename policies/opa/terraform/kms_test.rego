package terraform.kms_test

import data.terraform.kms
import rego.v1

key(after) := {"resource_changes": [{"address": "aws_kms_key.k", "type": "aws_kms_key", "change": {"actions": ["create"], "after": after}}]}

test_rotation_disabled_denied if {
	count(kms.deny) == 1 with input as key({"enable_key_rotation": false})
}

test_rotation_enabled_allowed if {
	count(kms.deny) == 0 with input as key({"enable_key_rotation": true, "deletion_window_in_days": 30})
	count(kms.warn) == 0 with input as key({"enable_key_rotation": true, "deletion_window_in_days": 30})
}

test_asymmetric_key_exempt if {
	count(kms.deny) == 0 with input as key({"customer_master_key_spec": "RSA_2048", "enable_key_rotation": false})
}

test_short_deletion_window_warns if {
	count(kms.warn) == 1 with input as key({"enable_key_rotation": true, "deletion_window_in_days": 7})
}
