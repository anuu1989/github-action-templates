# EC2: approved instance families only, IMDSv2 required.
package terraform.ec2

import data.terraform.lib
import rego.v1

# Override per environment with conftest --data (data.allowed_instance_families).
default_families := {"t3", "t3a", "t4g", "m6i", "m7i", "m7g", "c7i", "c7g", "r7i", "r7g"}

allowed_families := {f | some f in data.allowed_instance_families} if {
	data.allowed_instance_families
} else := default_families

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_instance"
	itype := rc.change.after.instance_type
	family := split(itype, ".")[0]
	not family in allowed_families
	msg := sprintf("%s uses instance type '%s'; allowed families: %v", [rc.address, itype, sort(allowed_families)])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type in {"aws_instance", "aws_launch_template"}
	not imdsv2_required(rc)
	msg := sprintf("%s must set metadata_options { http_tokens = \"required\" } (IMDSv2)", [rc.address])
}

imdsv2_required(rc) if {
	some mo in lib.as_array(object.get(rc.change.after, "metadata_options", []))
	mo.http_tokens == "required"
}
