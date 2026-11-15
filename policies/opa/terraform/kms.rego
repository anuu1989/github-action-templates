# KMS: rotation on symmetric keys, sane deletion window.
package terraform.kms

import data.terraform.lib
import rego.v1

symmetric(after) if object.get(after, "customer_master_key_spec", "SYMMETRIC_DEFAULT") in {"SYMMETRIC_DEFAULT", null}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_kms_key"
	symmetric(rc.change.after)
	object.get(rc.change.after, "enable_key_rotation", false) != true
	msg := sprintf("%s must set enable_key_rotation = true", [rc.address])
}

warn contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_kms_key"
	days := object.get(rc.change.after, "deletion_window_in_days", 30)
	is_number(days)
	days < 14
	msg := sprintf("%s deletion_window_in_days = %d: use >= 14 to allow recovery", [rc.address, days])
}
