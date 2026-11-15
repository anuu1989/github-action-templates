package terraform.logging_test

import data.terraform.logging
import rego.v1

plan(type, after) := {"resource_changes": [{
	"address": sprintf("%s.this", [type]),
	"type": type,
	"change": {"actions": ["create"], "after": after},
}]}

test_log_group_without_retention_denied if {
	count(logging.deny) == 1 with input as plan("aws_cloudwatch_log_group", {"retention_in_days": 0})
}

test_log_group_with_retention_allowed if {
	count(logging.deny) == 0 with input as plan("aws_cloudwatch_log_group", {"retention_in_days": 90})
}

test_single_region_trail_denied if {
	count(logging.deny) == 1 with input as plan("aws_cloudtrail", {"is_multi_region_trail": false, "enable_log_file_validation": true})
}

test_eks_without_audit_denied if {
	count(logging.deny) == 1 with input as plan("aws_eks_cluster", {"enabled_cluster_log_types": ["api"]})
}

test_vpc_without_flow_log_warns if {
	count(logging.warn) == 1 with input as plan("aws_vpc", {"cidr_block": "10.0.0.0/16"})
}

test_vpc_with_flow_log_ok if {
	p := {"resource_changes": [
		{"address": "aws_vpc.main", "type": "aws_vpc", "change": {"actions": ["create"], "after": {}}},
		{"address": "aws_flow_log.main", "type": "aws_flow_log", "change": {"actions": ["create"], "after": {"log_destination_type": "s3"}}},
	]}
	count(logging.warn) == 0 with input as p
}
