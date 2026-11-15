package docker_test

import data.docker
import rego.v1

good := [
	{"Cmd": "from", "Value": ["maven:3.9-eclipse-temurin-21", "AS", "build"]},
	{"Cmd": "run", "Value": ["mvn -B package"]},
	{"Cmd": "from", "Value": ["eclipse-temurin:21-jre-alpine"]},
	{"Cmd": "copy", "Value": ["--from=build", "/app/target/app.jar", "/app.jar"]},
	{"Cmd": "user", "Value": ["10001"]},
	{"Cmd": "healthcheck", "Value": ["CMD", "wget -qO- localhost:8080/health"]},
	{"Cmd": "entrypoint", "Value": ["java", "-jar", "/app.jar"]},
]

test_good_dockerfile_passes if {
	count(docker.deny) == 0 with input as good
	count(docker.warn) == 0 with input as good
}

test_stage_alias_not_flagged_as_untagged if {
	df := array.concat(good, [{"Cmd": "from", "Value": ["build"]}, {"Cmd": "user", "Value": ["app"]}])
	count(docker.deny) == 0 with input as df
}

test_latest_and_root_denied if {
	df := [{"Cmd": "from", "Value": ["node:latest"]}, {"Cmd": "user", "Value": ["root"]}]
	count(docker.deny) == 2 with input as df
}

test_untagged_and_no_user_denied if {
	count(docker.deny) == 2 with input as [{"Cmd": "from", "Value": ["ubuntu"]}]
}

test_secret_env_denied if {
	df := array.concat(good, [{"Cmd": "env", "Value": ["DB_PASSWORD", "hunter2"]}])
	count(docker.deny) == 1 with input as df
}

test_curl_pipe_sh_warns if {
	df := array.concat(good, [{"Cmd": "run", "Value": ["curl -sSL https://x.sh | bash"]}])
	count(docker.warn) == 1 with input as df
}
