# Audit & observability: log retention, CloudTrail, EKS audit logs, LB access logs, VPC flow logs.
package terraform.logging

import data.terraform.lib
import rego.v1

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_cloudwatch_log_group"
	object.get(rc.change.after, "retention_in_days", 0) in {0, null}
	msg := sprintf("%s must set retention_in_days (never-expire logs grow cost forever)", [rc.address])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_cloudtrail"
	some attr in ["is_multi_region_trail", "enable_log_file_validation"]
	object.get(rc.change.after, attr, false) != true
	msg := sprintf("%s must set %s = true", [rc.address, attr])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_eks_cluster"
	not "audit" in lib.as_array(object.get(rc.change.after, "enabled_cluster_log_types", []))
	msg := sprintf("%s must enable the 'audit' control-plane log type", [rc.address])
}

warn contains msg if {
	some rc in lib.resources_changing
	rc.type in {"aws_lb", "aws_alb"}
	object.get(lib.block(rc.change.after, "access_logs"), "enabled", false) != true
	msg := sprintf("%s should enable access_logs", [rc.address])
}

warn contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_vpc"
	"create" in rc.change.actions
	count([f | some f in input.resource_changes; f.type == "aws_flow_log"]) == 0
	msg := sprintf("%s is created without any aws_flow_log in this plan", [rc.address])
}
