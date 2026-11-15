package terraform.network_test

import data.terraform.network
import rego.v1

plan(type, after) := {"resource_changes": [{
	"address": sprintf("%s.this", [type]),
	"type": type,
	"change": {"actions": ["create"], "after": after},
}]}

test_http_forward_listener_denied if {
	count(network.deny) == 1 with input as plan("aws_lb_listener", {"protocol": "HTTP", "default_action": [{"type": "forward"}]})
}

test_http_redirect_listener_allowed if {
	count(network.deny) == 0 with input as plan("aws_lb_listener", {"protocol": "HTTP", "default_action": [{"type": "redirect"}]})
}

test_old_tls_policy_denied if {
	count(network.deny) == 1 with input as plan("aws_lb_listener", {"protocol": "HTTPS", "ssl_policy": "ELBSecurityPolicy-2016-08", "default_action": [{"type": "forward"}]})
}

test_modern_tls_policy_allowed if {
	count(network.deny) == 0 with input as plan("aws_lb_listener", {"protocol": "HTTPS", "ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06", "default_action": [{"type": "forward"}]})
}

test_public_eks_endpoint_denied if {
	count(network.deny) == 1 with input as plan("aws_eks_cluster", {"vpc_config": [{"endpoint_public_access": true, "public_access_cidrs": ["0.0.0.0/0"]}]})
}

test_restricted_eks_endpoint_allowed if {
	count(network.deny) == 0 with input as plan("aws_eks_cluster", {"vpc_config": [{"endpoint_public_access": true, "public_access_cidrs": ["203.0.113.0/24"]}]})
}

test_cloudfront_allow_all_and_old_tls_denied if {
	count(network.deny) == 2 with input as plan("aws_cloudfront_distribution", {
		"default_cache_behavior": [{"viewer_protocol_policy": "allow-all"}],
		"viewer_certificate": [{"cloudfront_default_certificate": false, "minimum_protocol_version": "TLSv1"}],
	})
}
