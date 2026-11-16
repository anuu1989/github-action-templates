#!/usr/bin/env bash
# End-to-end scenario tests for policies/opa using real conftest parsing.
#   - every *pass* fixture must produce zero failures
#   - every *fail* fixture must fail AND print every line listed in its .expected file
# Usage: tests/run-conftest-fixtures.sh   (CONFTEST=/path/to/conftest to override)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
CONFTEST="${CONFTEST:-conftest}"
FIX=tests/fixtures/opa
status=0

check_pass() { # domain file...
  local domain=$1; shift
  if out=$($CONFTEST test --no-color --all-namespaces -p "policies/opa/$domain" "$@" 2>&1); then
    echo "PASS  [$domain] $* (no failures)"
  else
    echo "FAIL  [$domain] $* expected no failures:"; echo "$out" | grep -E '^FAIL' | sed 's/^/      /'
    status=1
  fi
}

check_fail() { # domain expected-file file...
  local domain=$1 expected=$2; shift 2
  out=$($CONFTEST test --no-color --all-namespaces -p "policies/opa/$domain" "$@" 2>&1) && {
    echo "FAIL  [$domain] $* expected failures but passed"; status=1; return; }
  local missing=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    grep -qF -- "$line" <<< "$out" || { echo "      missing finding: $line"; missing=1; }
  done < "$expected"
  if [ $missing -eq 0 ]; then
    echo "PASS  [$domain] $* ($(grep -c '^FAIL' <<< "$out") failures, all $(grep -c . "$expected") expected findings present)"
  else
    echo "FAIL  [$domain] $*"; status=1
  fi
}

check_pass terraform      "$FIX/terraform/plan-pass.json"
check_fail terraform      "$FIX/terraform/plan-fail.expected" "$FIX/terraform/plan-fail.json"
check_pass kubernetes     "$FIX/kubernetes/pass.yaml"
check_fail kubernetes     "$FIX/kubernetes/fail.expected" "$FIX/kubernetes/fail.yaml"
check_pass docker         "$FIX/docker/pass/Dockerfile"
check_fail docker         "$FIX/docker/fail.expected" "$FIX/docker/fail/Dockerfile"
check_pass github-actions "$FIX/github-actions/pass.yml"
check_fail github-actions "$FIX/github-actions/fail.expected" "$FIX/github-actions/fail.yml"

# Dogfood: this repository's own workflows must have no policy failures
check_pass github-actions .github/workflows/*.yml examples/*.yml

exit $status
