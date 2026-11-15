package terraform.security_groups_test

import data.terraform.security_groups
import rego.v1

rc(type, after) := {"resource_changes": [{
	"address": sprintf("%s.this", [type]),
	"type": type,
	"change": {"actions": ["create"], "after": after},
}]}

test_inline_ssh_open_denied if {
	result := security_groups.deny with input as rc("aws_security_group", {"ingress": [{
		"from_port": 22, "to_port": 22, "protocol": "tcp",
		"cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": [],
	}]})
	count(result) == 1
}

test_inline_https_open_allowed if {
	result := security_groups.deny with input as rc("aws_security_group", {"ingress": [{
		"from_port": 443, "to_port": 443, "protocol": "tcp",
		"cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": null,
	}]})
	count(result) == 0
}

test_ssh_from_private_cidr_allowed if {
	result := security_groups.deny with input as rc("aws_security_group_rule", {
		"type": "ingress", "from_port": 22, "to_port": 22, "protocol": "tcp",
		"cidr_blocks": ["10.0.0.0/8"],
	})
	count(result) == 0
}

test_port_range_covering_rdp_denied if {
	result := security_groups.deny with input as rc("aws_security_group_rule", {
		"type": "ingress", "from_port": 3000, "to_port": 4000, "protocol": "tcp",
		"cidr_blocks": ["0.0.0.0/0"],
	})
	count(result) == 1
}

test_vpc_rule_all_traffic_denied if {
	result := security_groups.deny with input as rc("aws_vpc_security_group_ingress_rule", {"ip_protocol": "-1", "cidr_ipv4": "0.0.0.0/0", "from_port": null, "to_port": null})
	count(result) == 2 # both 22 and 3389
}

test_vpc_rule_ipv6_ssh_denied if {
	result := security_groups.deny with input as rc("aws_vpc_security_group_ingress_rule", {"ip_protocol": "tcp", "cidr_ipv6": "::/0", "from_port": 22, "to_port": 22})
	count(result) == 1
}
