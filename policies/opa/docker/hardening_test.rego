package docker.hardening_test

import data.docker
import rego.v1

base := [
	{"Cmd": "from", "Value": ["python:3.12-slim"]},
	{"Cmd": "user", "Value": ["10001"]},
	{"Cmd": "healthcheck", "Value": ["CMD", "true"]},
]

df(extra) := array.concat(base, extra)

test_expose_ssh_denied if {
	count(docker.deny) == 1 with input as df([{"Cmd": "expose", "Value": ["22/tcp"]}])
}

test_chmod_777_and_insecure_curl_denied if {
	count(docker.deny) == 2 with input as df([
		{"Cmd": "run", "Value": ["chmod -R 777 /app"]},
		{"Cmd": "run", "Value": ["curl -k -o x.tgz https://example.com/x.tgz"]},
	])
}

test_apt_without_hygiene_warns if {
	count(docker.warn) == 2 with input as df([{"Cmd": "run", "Value": ["apt-get update && apt-get install -y curl"]}])
}

test_apt_with_hygiene_clean if {
	v := "apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*"
	count(docker.warn) == 0 with input as df([{"Cmd": "run", "Value": [v]}])
}

test_pip_and_apk_warn if {
	count(docker.warn) == 2 with input as df([
		{"Cmd": "run", "Value": ["pip install -r requirements.txt"]},
		{"Cmd": "run", "Value": ["apk add curl"]},
	])
}

test_shell_form_entrypoint_and_relative_workdir_warn if {
	count(docker.warn) == 2 with input as df([
		{"Cmd": "workdir", "Value": ["app"]},
		{"Cmd": "entrypoint", "Value": ["python app.py"], "JSON": false},
	])
}

test_exec_form_clean if {
	count(docker.warn) == 0 with input as df([{"Cmd": "entrypoint", "Value": ["python", "app.py"], "JSON": true}])
}

test_registry_allowlist_opt_in if {
	count(docker.deny) == 0 with input as base
	count(docker.deny) == 1 with input as base with data.allowed_base_registries as ["public.ecr.aws/"]
	approved := json.patch(base, [{"op": "replace", "path": "/0/Value/0", "value": "public.ecr.aws/docker/library/python:3.12"}])
	count(docker.deny) == 0 with input as approved with data.allowed_base_registries as ["public.ecr.aws/"]
}
