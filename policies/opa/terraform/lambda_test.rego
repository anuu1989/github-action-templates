package terraform.lambda_test

import data.terraform.lambda
import rego.v1

plan(type, after) := {"resource_changes": [{
	"address": sprintf("%s.this", [type]),
	"type": type,
	"change": {"actions": ["create"], "after": after},
}]}

test_public_function_url_denied if {
	count(lambda.deny) == 1 with input as plan("aws_lambda_function_url", {"authorization_type": "NONE"})
}

test_iam_function_url_allowed if {
	count(lambda.deny) == 0 with input as plan("aws_lambda_function_url", {"authorization_type": "AWS_IAM"})
}

test_wildcard_permission_denied if {
	count(lambda.deny) == 1 with input as plan("aws_lambda_permission", {"principal": "*"})
}

test_s3_permission_without_source_warns if {
	count(lambda.warn) == 1 with input as plan("aws_lambda_permission", {"principal": "s3.amazonaws.com"})
}

test_deprecated_runtime_and_secret_env_denied if {
	count(lambda.deny) == 2 with input as plan("aws_lambda_function", {
		"runtime": "python3.8",
		"environment": [{"variables": {"DB_PASSWORD": "x", "LOG_LEVEL": "info"}}],
		"tracing_config": [{"mode": "Active"}],
	})
}

test_compliant_function if {
	f := plan("aws_lambda_function", {"runtime": "python3.12", "environment": [{"variables": {"LOG_LEVEL": "info"}}], "tracing_config": [{"mode": "Active"}]})
	count(lambda.deny) == 0 with input as f
	count(lambda.warn) == 0 with input as f
}
