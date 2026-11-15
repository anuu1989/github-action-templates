# Additional Dockerfile hardening & image-size hygiene (same `docker` package as dockerfile.rego).
package docker

import rego.v1

run_cmds := [v | some cmd in input; cmd.Cmd == "run"; some v in cmd.Value]

deny contains msg if {
	some cmd in input
	cmd.Cmd == "expose"
	some port in cmd.Value
	split(port, "/")[0] in {"22", "23", "3389"}
	msg := sprintf("EXPOSE %s: remote-shell ports must not be exposed", [port])
}

deny contains msg if {
	some v in run_cmds
	regex.match(`chmod\s+(-R\s+)?(0?777|a\+rwx)`, v)
	msg := "Do not chmod 777: grant the minimum permissions needed"
}

deny contains msg if {
	some v in run_cmds
	regex.match(`(curl|wget)\s[^|;&]*(-k|--insecure|--no-check-certificate)`, v)
	msg := "Do not disable TLS verification when downloading (curl -k / wget --no-check-certificate)"
}

warn contains msg if {
	some v in run_cmds
	contains(v, "apt-get install")
	not contains(v, "--no-install-recommends")
	msg := "apt-get install should use --no-install-recommends"
}

warn contains msg if {
	some v in run_cmds
	contains(v, "apt-get install")
	not contains(v, "rm -rf /var/lib/apt/lists")
	msg := "Clean apt lists in the same layer: rm -rf /var/lib/apt/lists/*"
}

warn contains msg if {
	some v in run_cmds
	contains(v, "apt-get upgrade")
	msg := "Avoid apt-get upgrade in images: rebuild from a patched base image instead"
}

warn contains msg if {
	some v in run_cmds
	regex.match(`apk\s+add`, v)
	not contains(v, "--no-cache")
	msg := "apk add should use --no-cache"
}

warn contains msg if {
	some v in run_cmds
	regex.match(`pip3?\s+install`, v)
	not contains(v, "--no-cache-dir")
	not contains(v, "--mount=type=cache")
	msg := "pip install should use --no-cache-dir (or a BuildKit cache mount)"
}

warn contains msg if {
	some cmd in input
	cmd.Cmd in {"cmd", "entrypoint"}
	cmd.JSON == false
	msg := sprintf("%s uses shell form: prefer exec form [\"bin\", \"arg\"] so signals reach the process", [upper(cmd.Cmd)])
}

warn contains msg if {
	some cmd in input
	cmd.Cmd == "workdir"
	not startswith(cmd.Value[0], "/")
	not startswith(cmd.Value[0], "$")
	msg := sprintf("WORKDIR %s should be an absolute path", [cmd.Value[0]])
}

# Opt-in registry allow-list: conftest --data with allowed_base_registries: ["public.ecr.aws/", "ghcr.io/acme/"]
deny contains msg if {
	data.allowed_base_registries
	some image in base_images
	image != "scratch"
	not lower(image) in stage_aliases
	not approved_base(image)
	msg := sprintf("FROM %s: base image is not from an approved registry", [image])
}

approved_base(image) if {
	some prefix in data.allowed_base_registries
	startswith(image, prefix)
}
