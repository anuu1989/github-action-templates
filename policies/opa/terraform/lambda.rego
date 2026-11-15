# Lambda: no anonymous function URLs / permissions, supported runtimes, no secrets in env vars.
package terraform.lambda

import data.terraform.lib
import rego.v1

deprecated_runtime_prefixes := ["python2", "python3.6", "python3.7", "python3.8", "nodejs1", "nodejs8", "nodejs10", "nodejs12", "nodejs14", "nodejs16", "java8", "go1.x", "ruby2", "dotnetcore", "dotnet5", "dotnet6"]

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_lambda_function_url"
	rc.change.after.authorization_type == "NONE"
	msg := sprintf("%s: function URL with authorization_type NONE is publicly invocable", [rc.address])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_lambda_permission"
	rc.change.after.principal == "*"
	msg := sprintf("%s grants invoke to principal \"*\"", [rc.address])
}

warn contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_lambda_permission"
	endswith(rc.change.after.principal, ".amazonaws.com")
	object.get(rc.change.after, "source_arn", null) in {null, ""}
	msg := sprintf("%s: service principal without source_arn (confused-deputy risk)", [rc.address])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_lambda_function"
	runtime := rc.change.after.runtime
	is_string(runtime)
	some prefix in deprecated_runtime_prefixes
	startswith(runtime, prefix)
	msg := sprintf("%s uses deprecated runtime '%s'", [rc.address, runtime])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_lambda_function"
	env := lib.block(rc.change.after, "environment")
	some name, _ in object.get(env, "variables", {})
	regex.match(`(?i)(password|passwd|secret|api_?key|private_?key|token)`, name)
	msg := sprintf("%s: env var '%s' looks like a secret: read it from Secrets Manager / SSM at runtime", [rc.address, name])
}

warn contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_lambda_function"
	object.get(lib.block(rc.change.after, "tracing_config"), "mode", "PassThrough") != "Active"
	msg := sprintf("%s should enable X-Ray tracing (tracing_config.mode = Active)", [rc.address])
}
