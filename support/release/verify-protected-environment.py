#!/usr/bin/env python3
"""Offline bounded validator for the release environment and tag policies.

Validates actual GitHub environment/tag-protection JSON snapshots against the
fail-closed release requirements without network access. GitHub deployment
branch and tag policies combine with OR, so the policies snapshot must contain
exactly one policy and that policy must be the narrow release tag rule;
anything broader fails closed. Reads only the two JSON files given on the
command line, prints only safe booleans and field names (never reviewer
identities or full JSON), and exits 0 on PASS or 1 on any failure.
Stdlib-only and offline.

Usage:
    python3 -B support/release/verify-protected-environment.py \\
        --environment-json <json> --policies-json <json> --tag <tag>
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from pathlib import Path

ALLOWED_TAG_PATTERN = "v0.1.0-testnet.*"
REJECTED_TAG_POLICIES = frozenset({"v*", "*", "**"})


class ProtectedEnvironmentError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProtectedEnvironmentError(message)


def load_json_file(path: Path, label: str) -> object:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ProtectedEnvironmentError(f"cannot read {label} JSON") from error
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtectedEnvironmentError(f"{label} JSON is not valid UTF-8") from error
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise ProtectedEnvironmentError(f"{label} JSON is malformed") from error


def _is_nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def validate_environment(data: object) -> dict:
    require(isinstance(data, dict), "environment JSON must be an object")
    env = data
    require("can_admins_bypass" in env, "environment JSON is missing field: can_admins_bypass")
    require(env["can_admins_bypass"] is False, "can_admins_bypass must be false")
    require(
        "deployment_branch_policy" in env,
        "environment JSON is missing field: deployment_branch_policy",
    )
    policy = env["deployment_branch_policy"]
    require(isinstance(policy, dict), "deployment_branch_policy must be an object")
    require(
        "custom_branch_policies" in policy,
        "environment JSON is missing field: deployment_branch_policy.custom_branch_policies",
    )
    require(
        policy["custom_branch_policies"] is True,
        "deployment_branch_policy.custom_branch_policies must be true",
    )
    require(
        "protected_branches" in policy,
        "environment JSON is missing field: deployment_branch_policy.protected_branches",
    )
    require(
        policy["protected_branches"] is False,
        "deployment_branch_policy.protected_branches must be false",
    )
    require("protection_rules" in env, "environment JSON is missing field: protection_rules")
    rules = env["protection_rules"]
    require(isinstance(rules, list), "protection_rules must be a list")
    reviewer_rules = [
        rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    require(
        len(reviewer_rules) == 1,
        "protection_rules must contain exactly one required_reviewers rule",
    )
    rule = reviewer_rules[0]
    require("reviewers" in rule, "required_reviewers rule is missing field: reviewers")
    reviewers = rule["reviewers"]
    require(isinstance(reviewers, list) and reviewers, "reviewers must be a non-empty list")
    def valid_reviewer(item: object) -> bool:
        if _is_nonempty_string(item):
            return True
        if not isinstance(item, dict):
            return False
        if item.get("type") not in ("User", "Team"):
            return False
        reviewer = item.get("reviewer")
        return isinstance(reviewer, (dict, str)) and bool(reviewer)

    require(
        all(valid_reviewer(item) for item in reviewers),
        "reviewers must be non-empty GitHub reviewer objects",
    )
    top_level = env.get("prevent_self_review")
    rule_level = rule.get("prevent_self_review")
    require(
        top_level is True or rule_level is True,
        "prevent_self_review must be true",
    )
    return {"reviewer_rule_count": 1, "reviewer_count": len(reviewers)}


def _policy_list(data: object) -> list:
    """Extract the single deployment policy; fail closed on any broadening.

    GitHub deployment branch and tag policies combine with OR, so any second
    policy widens the gate. Exactly one policy must remain after parsing the
    supported shapes (bare list, ``branch_policies`` mapping, or ``policies``
    mapping).
    """
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("branch_policies", "policies"):
            if key in data:
                items = data[key]
                require(isinstance(items, list), f"{key} must be a list")
                break
        else:
            raise ProtectedEnvironmentError(
                "policies JSON is missing field: branch_policies or policies"
            )
    else:
        raise ProtectedEnvironmentError("policies JSON must be an object or a list")
    require(
        len(items) == 1,
        "policies list must contain exactly one policy; branch and tag policies combine with OR",
    )
    return items


def validate_policies(data: object, tag: str) -> dict:
    require(_is_nonempty_string(tag), "--tag must be a non-empty string")
    items = _policy_list(data)
    policy = items[0]
    require(isinstance(policy, dict), "policies[0] must be an object")
    require(
        policy.get("type") == "tag",
        "the single policy must have type: tag; branch policies broaden the gate and are rejected",
    )
    require(_is_nonempty_string(policy.get("name")), "policies[0] is missing field: name")
    name = policy["name"]
    require(
        name not in REJECTED_TAG_POLICIES,
        "policies[0] tag policy is overbroad and rejected",
    )
    require(
        name == ALLOWED_TAG_PATTERN or name == tag,
        "policies[0] tag policy name must be exactly the allowed pattern or the exact release tag",
    )
    require(
        fnmatch.fnmatch(tag, ALLOWED_TAG_PATTERN),
        "release tag does not match the allowed tag pattern",
    )
    return {"tag_policy_count": 1, "tag_policy_matched": name}


def verify(environment_path: Path, policies_path: Path, tag: str) -> dict:
    environment_data = load_json_file(environment_path, "environment")
    policies_data = load_json_file(policies_path, "policies")
    env_summary = validate_environment(environment_data)
    policy_summary = validate_policies(policies_data, tag)
    return {
        "status": "PASS",
        "tag": tag,
        "environment_protected": True,
        "can_admins_bypass": False,
        "prevent_self_review": True,
        "custom_branch_policies": True,
        "protected_branches": False,
        "reviewer_rule_count": env_summary["reviewer_rule_count"],
        "reviewer_count": env_summary["reviewer_count"],
        "tag_policy_matched": policy_summary["tag_policy_matched"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline validator for release environment and tag policies."
    )
    parser.add_argument("--environment-json", required=True, type=Path)
    parser.add_argument("--policies-json", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args(argv)
    try:
        result = verify(args.environment_json, args.policies_json, args.tag)
    except ProtectedEnvironmentError as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}, indent=2), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"status": "FAIL", "error": "filesystem error"}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
