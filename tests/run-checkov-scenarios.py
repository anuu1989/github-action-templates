#!/usr/bin/env python3
"""Scenario tests for the Checkov custom checks in policies/checkov/custom_checks.

For every custom check ID it asserts that the set of PASSED and FAILED resources produced by Checkov
over tests/fixtures/checkov exactly matches tests/fixtures/checkov/expected.json, and that every
custom check has at least one passing and one failing scenario.

Usage:
  python tests/run-checkov-scenarios.py                    # runs `checkov` from PATH
  python tests/run-checkov-scenarios.py --results out.json # evaluate an existing `checkov -o json` result
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKS_DIR = ROOT / "policies/checkov/custom_checks"
FIXTURES = ROOT / "tests/fixtures/checkov"
ID_RE = re.compile(r"\bCKV2?_ORG_\d+\b")


def custom_check_ids() -> list[str]:
    ids: set[str] = set()
    for f in CHECKS_DIR.glob("*"):
        if f.suffix in {".py", ".yaml", ".yml"} and f.name != "__init__.py":
            ids.update(ID_RE.findall(f.read_text()))
    return sorted(ids, key=lambda i: (i.startswith("CKV2"), int(i.rsplit("_", 1)[1])))


def run_checkov(ids: list[str]) -> list | dict:
    cmd = [
        "checkov", "-d", str(FIXTURES), "--external-checks-dir", str(CHECKS_DIR),
        "--check", ",".join(ids), "--framework", "terraform", "kubernetes", "dockerfile", "cloudformation",
        "-o", "json", "--skip-download",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    if not proc.stdout.strip():
        sys.exit(f"checkov produced no output:\n{proc.stderr}")
    return json.loads(proc.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", help="existing checkov JSON output")
    args = parser.parse_args()

    ids = custom_check_ids()
    raw = json.loads(Path(args.results).read_text()) if args.results else run_checkov(ids)
    reports = raw if isinstance(raw, list) else [raw]

    actual: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"pass": set(), "fail": set()})
    for report in reports:
        results = report.get("results", {})
        for key, outcome in (("passed_checks", "pass"), ("failed_checks", "fail")):
            for r in results.get(key, []):
                actual[r["check_id"]][outcome].add(r["resource"])

    expected = json.loads((FIXTURES / "expected.json").read_text())
    failures = 0
    print(f"{'CHECK':<12} {'PASS':>4} {'FAIL':>4}  RESULT")
    for check_id in ids:
        exp = expected.get(check_id)
        got = actual.get(check_id, {"pass": set(), "fail": set()})
        problems = []
        if exp is None:
            problems.append("no scenarios in expected.json")
        else:
            for outcome in ("pass", "fail"):
                want = set(exp[outcome])
                if not want:
                    problems.append(f"needs at least one '{outcome}' scenario")
                if missing := want - got[outcome]:
                    problems.append(f"expected {outcome} but not reported {outcome}: {sorted(missing)}")
                if extra := got[outcome] - want:
                    problems.append(f"unexpected {outcome}: {sorted(extra)}")
        status = "ok" if not problems else "MISMATCH"
        print(f"{check_id:<12} {len(got['pass']):>4} {len(got['fail']):>4}  {status}")
        for p in problems:
            print(f"             - {p}")
        failures += bool(problems)

    if unknown := set(expected) - set(ids):
        print(f"expected.json references unknown checks: {sorted(unknown)}")
        failures += 1
    print(f"\n{len(ids) - failures}/{len(ids)} custom checks match their scenarios")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
