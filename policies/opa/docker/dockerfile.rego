# Dockerfile best practices (conftest's dockerfile parser: input is a list of instructions).
package docker

import rego.v1

stage_aliases contains lower(cmd.Value[2]) if {
	some cmd in input
	cmd.Cmd == "from"
	count(cmd.Value) == 3
	lower(cmd.Value[1]) == "as"
}

base_images contains cmd.Value[0] if {
	some cmd in input
	cmd.Cmd == "from"
}

deny contains msg if {
	some image in base_images
	endswith(image, ":latest")
	msg := sprintf("FROM %s: do not use the 'latest' tag", [image])
}

deny contains msg if {
	some image in base_images
	image != "scratch"
	not lower(image) in stage_aliases
	not contains(image, "@")
	parts := split(image, "/")
	not contains(parts[count(parts) - 1], ":")
	msg := sprintf("FROM %s: pin the base image to a tag or digest", [image])
}

user_cmds := [cmd | some cmd in input; cmd.Cmd == "user"]

# Conftest's dockerfile parser yields a list of instructions; guard "absence" rules so they never
# fire on other inputs (e.g. a Terraform plan) when the whole policy library is evaluated at once.
is_dockerfile if {
	is_array(input)
	some cmd in input
	cmd.Cmd == "from"
}

deny contains "Dockerfile must switch to a non-root USER" if {
	is_dockerfile
	count(user_cmds) == 0
}

deny contains msg if {
	count(user_cmds) > 0
	last := user_cmds[count(user_cmds) - 1]
	split(last.Value[0], ":")[0] in {"root", "0"}
	msg := sprintf("Final USER is '%s': run as a non-root user", [last.Value[0]])
}

deny contains msg if {
	some cmd in input
	cmd.Cmd == "run"
	some v in cmd.Value
	regex.match(`(^|\s|;|&&)sudo\s`, v)
	msg := "Do not use sudo in RUN instructions"
}

deny contains msg if {
	some cmd in input
	cmd.Cmd in {"env", "arg"}
	some v in cmd.Value
	regex.match(`(?i)(password|passwd|secret|api_?key|access_?key|token)`, v)
	msg := sprintf("%s '%s' looks like a secret: use build secrets (--mount=type=secret) instead", [upper(cmd.Cmd), v])
}

warn contains msg if {
	some cmd in input
	cmd.Cmd == "add"
	msg := sprintf("ADD %v: prefer COPY unless you need archive extraction", [cmd.Value])
}

warn contains msg if {
	some cmd in input
	cmd.Cmd == "run"
	some v in cmd.Value
	regex.match(`(curl|wget)[^|]*\|\s*(ba)?sh`, v)
	msg := "Avoid piping remote scripts into a shell (curl | sh)"
}

warn contains "Consider adding a HEALTHCHECK instruction" if {
	is_dockerfile
	not any_healthcheck
}

any_healthcheck if {
	some cmd in input
	cmd.Cmd == "healthcheck"
}
