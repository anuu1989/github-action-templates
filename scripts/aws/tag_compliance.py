#!/usr/bin/env python3
"""Report AWS resources that are missing required tags (boto3 / Resource Groups Tagging API).

Usage:
  python tag_compliance.py --required-tags Owner,Environment,CostCenter [--regions us-east-1,eu-west-1] \
      [--resource-types ec2:instance,s3:bucket] [--fail]

Writes a Markdown report to stdout (and $GITHUB_STEP_SUMMARY when running in Actions).
Exits 1 with --fail if any non-compliant resources are found.
"""
from __future__ import annotations

import argparse
import os
import sys

import boto3
from botocore.config import Config

RETRY = Config(retries={"max_attempts": 10, "mode": "adaptive"})


def scan_region(region: str, required: set[str], resource_types: list[str]) -> list[dict]:
    client = boto3.client("resourcegroupstaggingapi", region_name=region, config=RETRY)
    paginator = client.get_paginator("get_resources")
    kwargs = {"ResourceTypeFilters": resource_types} if resource_types else {}
    findings = []
    for page in paginator.paginate(**kwargs):
        for res in page["ResourceTagMappingList"]:
            keys = {t["Key"] for t in res.get("Tags", [])}
            missing = sorted(required - keys)
            if missing:
                findings.append({"region": region, "arn": res["ResourceARN"], "missing": missing})
    return findings


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--required-tags", required=True)
    p.add_argument("--regions", default=os.environ.get("AWS_REGION", "us-east-1"))
    p.add_argument("--resource-types", default="")
    p.add_argument("--fail", action="store_true")
    args = p.parse_args()

    required = {t.strip() for t in args.required_tags.split(",") if t.strip()}
    types = [t.strip() for t in args.resource_types.split(",") if t.strip()]
    account = boto3.client("sts").get_caller_identity()["Account"]

    findings: list[dict] = []
    for region in [r.strip() for r in args.regions.split(",") if r.strip()]:
        findings.extend(scan_region(region, required, types))

    lines = [f"## Tag compliance: account `{account}`", ""]
    if not findings:
        lines.append(f":white_check_mark: All resources carry {sorted(required)}")
    else:
        lines += [f":x: **{len(findings)}** resources missing required tags", "",
                  "| Region | Resource | Missing |", "|---|---|---|"]
        lines += [f"| {f['region']} | `{f['arn']}` | {', '.join(f['missing'])} |" for f in findings[:500]]
        if len(findings) > 500:
            lines.append(f"\n_...and {len(findings) - 500} more_")
    report = "\n".join(lines)
    print(report)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report + "\n")
    return 1 if (findings and args.fail) else 0


if __name__ == "__main__":
    sys.exit(main())
