# No SSH / RDP open to the internet: covers inline ingress blocks, aws_security_group_rule
# and aws_vpc_security_group_ingress_rule.
package terraform.security_groups

import data.terraform.lib
import rego.v1

restricted_ports := {22, 3389}

open_cidrs := {"0.0.0.0/0", "::/0"}

exposes(_, _, protocol, _) if protocol in {"-1", "all"}

exposes(from, to, protocol, port) if {
	not protocol in {"-1", "all"}
	from <= port
	port <= to
}

# Inline ingress on aws_security_group
deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_security_group"
	some rule in lib.as_array(object.get(rc.change.after, "ingress", []))
	cidrs := array.concat(
		lib.as_array(object.get(rule, "cidr_blocks", [])),
		lib.as_array(object.get(rule, "ipv6_cidr_blocks", [])),
	)
	some cidr in cidrs
	cidr in open_cidrs
	some port in restricted_ports
	exposes(rule.from_port, rule.to_port, rule.protocol, port)
	msg := sprintf("%s allows ingress from %s to port %d", [rc.address, cidr, port])
}

# Legacy standalone rule resource
deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_security_group_rule"
	rule := rc.change.after
	rule.type == "ingress"
	cidrs := array.concat(
		lib.as_array(object.get(rule, "cidr_blocks", [])),
		lib.as_array(object.get(rule, "ipv6_cidr_blocks", [])),
	)
	some cidr in cidrs
	cidr in open_cidrs
	some port in restricted_ports
	exposes(rule.from_port, rule.to_port, rule.protocol, port)
	msg := sprintf("%s allows ingress from %s to port %d", [rc.address, cidr, port])
}

# Modern per-rule resource
deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_vpc_security_group_ingress_rule"
	rule := rc.change.after
	some cidr in [object.get(rule, "cidr_ipv4", null), object.get(rule, "cidr_ipv6", null)]
	cidr in open_cidrs
	some port in restricted_ports
	exposes(object.get(rule, "from_port", null), object.get(rule, "to_port", null), rule.ip_protocol, port)
	msg := sprintf("%s allows ingress from %s to port %d", [rc.address, cidr, port])
}
