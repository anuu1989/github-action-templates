# Network edge: HTTPS-only load balancers & CloudFront with modern TLS, private EKS endpoints.
package terraform.network

import data.terraform.lib
import rego.v1

modern_tls_policy(p) if regex.match(`TLS13|TLS-1-2|FS-1-2`, p)

deny contains msg if {
	some rc in lib.resources_changing
	rc.type in {"aws_lb_listener", "aws_alb_listener"}
	rc.change.after.protocol == "HTTP"
	action := lib.block(rc.change.after, "default_action")
	action.type != "redirect"
	msg := sprintf("%s: HTTP listeners must redirect to HTTPS", [rc.address])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type in {"aws_lb_listener", "aws_alb_listener"}
	rc.change.after.protocol in {"HTTPS", "TLS"}
	policy := object.get(rc.change.after, "ssl_policy", "")
	not modern_tls_policy(policy)
	msg := sprintf("%s uses ssl_policy '%s': require a TLS 1.2+ policy (e.g. ELBSecurityPolicy-TLS13-1-2-2021-06)", [rc.address, policy])
}

warn contains msg if {
	some rc in lib.resources_changing
	rc.type in {"aws_lb", "aws_alb"}
	object.get(rc.change.after, "load_balancer_type", "application") == "application"
	object.get(rc.change.after, "drop_invalid_header_fields", false) != true
	msg := sprintf("%s should set drop_invalid_header_fields = true", [rc.address])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_eks_cluster"
	vpc := lib.block(rc.change.after, "vpc_config")
	vpc.endpoint_public_access == true
	"0.0.0.0/0" in lib.as_array(object.get(vpc, "public_access_cidrs", ["0.0.0.0/0"]))
	msg := sprintf("%s: public API endpoint open to 0.0.0.0/0: restrict public_access_cidrs or disable public access", [rc.address])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_cloudfront_distribution"
	behavior := lib.block(rc.change.after, "default_cache_behavior")
	behavior.viewer_protocol_policy == "allow-all"
	msg := sprintf("%s: viewer_protocol_policy must be redirect-to-https or https-only", [rc.address])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_cloudfront_distribution"
	cert := lib.block(rc.change.after, "viewer_certificate")
	object.get(cert, "cloudfront_default_certificate", false) != true
	not startswith(object.get(cert, "minimum_protocol_version", ""), "TLSv1.2")
	msg := sprintf("%s: minimum_protocol_version must be TLSv1.2_2021 or newer", [rc.address])
}

warn contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_subnet"
	rc.change.after.map_public_ip_on_launch == true
	msg := sprintf("%s auto-assigns public IPs", [rc.address])
}
