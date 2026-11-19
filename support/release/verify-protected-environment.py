#!/usr/bin/env python3
"""Offline bounded validator for the protected `release` environment (no App, Phase1).

Validates actual GitHub environment/tag-protection JSON snapshots against the
fail-closed, version-scoped owner self-approval requirements without network
access. Phase1 automation validates ONLY ``release`` (package/draft mutation
jobs) via ``--expected-environment release`` (the default). ``release-admin``
remains supported as ``--expected-environment`` for manual owner checks
OUTSIDE the workflow only; it is NOT used by automation, and no App, private
key, installation token, or extra secret is used.

Both environments share the same policy when checked: owner sole self-approval
(User 86115037), ``prevent_self_review`` exactly false, ``can_admins_bypass``
false, and the exact current release tag ``v0.1.0-testnet.5`` with no
wildcards. GitHub deployment branch and tag policies combine with OR, so the
policies snapshot must contain exactly one policy and that policy must be the
exact current release tag; anything broader fails closed. The
deployment-policy response must include a ``total_count`` that equals the
number of returned policies so a paginated response cannot hide a second,
broadening policy.

The required reviewer is pinned to the owner's immutable numeric GitHub user id
(86115037) and login. ``prevent_self_review`` must be exactly false because the
owner explicitly authorized owner self-approval; this is a documented reduction
in separation of duties, not independent review. Admin bypass must be false and
the environment must use custom tag policies. Sequencing note (temporal,
non-atomic, TOCTOU): environment approvals can introduce delays between a
check and a later mutation, so no check is atomic or immediate and same-run
``needs`` does NOT inherit SHA/tag binding; each job independently verifies its
own gate live, the draft remains mutable by repository writers until
publication, and manual prepublish recheck (environment, split tag rulesets
with the owner credential, immutable-releases flag, every draft asset digest,
draft body) remains required immediately before manual publication. Reads only
the two JSON files given on the command line, prints only safe booleans and
field names (never reviewer identities or full JSON), and exits 0 on PASS or 1
on any failure. Stdlib-only and offline. No publication comes from automation;
the workflow creates and verifies a draft prerelease only.

Usage:
    python3 -B support/release/verify-protected-environment.py \\
        --environment-json <json> --policies-json <json> --tag <tag> \\
        [--expected-environment release|release-admin]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

EXPECTED_RELEASE_TAG = "v0.1.0-testnet.5"
EXPECTED_REVIEWER_ID = 86115037
EXPECTED_REVIEWER_LOGIN = "emyrinj"
RELEASE_TAG_PATTERN = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+-testnet\.[0-9]+$")


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


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_environment(data: object, expected_environment: str = "release") -> dict:
    require(isinstance(data, dict), "environment JSON must be an object")
    require(
        expected_environment in ("release", "release-admin"),
        "expected environment must be release or release-admin",
    )
    env = data
    require("name" in env, "environment JSON is missing field: name")
    if expected_environment == "release-admin":
        require(env["name"] == "release-admin", "environment name must be exactly release-admin")
    else:
        require(env["name"] == "release", "environment name must be exactly release")
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
    require(
        len(reviewers) == 1,
        "reviewers must contain exactly the owner reviewer; team or additional reviewers are not accepted for owner self-approval",
    )
    reviewer = reviewers[0]
    require(isinstance(reviewer, dict), "reviewer entry must be an object")
    require(reviewer.get("type") == "User", "reviewer type must be exactly User")
    nested = reviewer.get("reviewer")
    require(isinstance(nested, dict), "reviewer.reviewer must be an object")
    reviewer_id = nested.get("id")
    require(_is_int(reviewer_id), "reviewer id must be an integer")
    require(
        reviewer_id == EXPECTED_REVIEWER_ID,
        "reviewer id must be the immutable owner id 86115037",
    )
    reviewer_login = nested.get("login")
    require(_is_nonempty_string(reviewer_login), "reviewer login must be a non-empty string")
    require(
        reviewer_login == EXPECTED_REVIEWER_LOGIN,
        "reviewer login must be the owner login",
    )
    # The owner model intentionally disables self-review prevention. Any True
    # value at either level is rejected so the approval policy cannot drift.
    top_level = env.get("prevent_self_review")
    if top_level is not None:
        require(
            top_level is False,
            "environment prevent_self_review must be false for the owner self-approval policy",
        )
    require(
        "prevent_self_review" in rule,
        "required_reviewers rule is missing field: prevent_self_review",
    )
    require(
        rule["prevent_self_review"] is False,
        "required_reviewers prevent_self_review must be exactly false for owner self-approval",
    )
    return {
        "reviewer_rule_count": 1,
        "reviewer_count": 1,
        "owner_reviewer_id_matched": True,
        "prevent_self_review": False,
        "owner_self_approval": True,
        "independent_review": False,
    }


def _policy_list(data: object) -> tuple[list, int]:
    """Extract the single deployment policy with a verified total count.

    GitHub returns ``{"total_count": N, "branch_policies": [...]}``. The
    pagination total is required: accepting a page without it could hide a
    second policy on another page, and GitHub policies combine with OR.
    """
    require(isinstance(data, dict), "policies JSON must be an object")
    require("total_count" in data, "policies JSON is missing field: total_count")
    total_count = data["total_count"]
    require(_is_int(total_count), "policies total_count must be an integer")
    require(total_count >= 0, "policies total_count must not be negative")
    present_keys = [
        key
        for key in ("branch_policies", "policies", "deployment_branch_policies")
        if key in data
    ]
    require(
        len(present_keys) == 1,
        "policies JSON must contain exactly one policy array field; ambiguous shapes are rejected",
    )
    require(
        set(data) == {"total_count", present_keys[0]},
        "policies JSON contains unexpected fields; refusing an ambiguous shape",
    )
    items = data[present_keys[0]]
    require(isinstance(items, list), "policies list must be a list")
    require(
        total_count == len(items),
        "policies total_count does not match the returned policy list; refusing a partial paginated response",
    )
    require(
        total_count == 1,
        "policies list must contain exactly one policy; branch and tag policies combine with OR",
    )
    require(
        total_count <= 100,
        "policies total_count exceeds the bounded per-page request; refusing ambiguous pagination",
    )
    return items, total_count


def validate_policies(data: object, tag: str) -> dict:
    require(_is_nonempty_string(tag), "--tag must be a non-empty string")
    require(
        tag == EXPECTED_RELEASE_TAG,
        "release tag must be exactly the current candidate v0.1.0-testnet.5",
    )
    require(
        RELEASE_TAG_PATTERN.fullmatch(tag) is not None,
        "release tag does not match the required release-tag pattern",
    )
    items, total_count = _policy_list(data)
    policy = items[0]
    require(isinstance(policy, dict), "policies[0] must be an object")
    require(
        policy.get("type") == "tag",
        "the single policy must have type: tag; branch policies broaden the gate and are rejected",
    )
    require(_is_nonempty_string(policy.get("name")), "policies[0] is missing field: name")
    name = policy["name"]
    require(
        not any(character in name for character in ("*", "?", "[", "]")),
        "policies[0] tag policy must be the exact tag, not a wildcard pattern",
    )
    require(
        name == tag,
        "policies[0] tag policy name must be exactly the release tag v0.1.0-testnet.5",
    )
    return {
        "tag_policy_count": 1,
        "tag_policy_matched": name,
        "pagination_total_count": total_count,
    }


def verify(environment_path: Path, policies_path: Path, tag: str, expected_environment: str = "release") -> dict:
    environment_data = load_json_file(environment_path, "environment")
    policies_data = load_json_file(policies_path, "policies")
    env_summary = validate_environment(environment_data, expected_environment)
    policy_summary = validate_policies(policies_data, tag)
    return {
        "status": "PASS",
        "tag": tag,
        "environment_protected": True,
        "can_admins_bypass": False,
        "prevent_self_review": False,
        "owner_self_approval": True,
        "independent_review": False,
        "owner_reviewer_id_matched": True,
        "custom_branch_policies": True,
        "protected_branches": False,
        "reviewer_rule_count": env_summary["reviewer_rule_count"],
        "reviewer_count": env_summary["reviewer_count"],
        "environment_name": expected_environment,
        "tag_policy_matched": policy_summary["tag_policy_matched"],
        "pagination_total_count_verified": True,
        "pagination_total_count": policy_summary["pagination_total_count"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline validator for the owner self-approval release and release-admin environments and exact tag policies."
    )
    parser.add_argument("--environment-json", required=True, type=Path)
    parser.add_argument("--policies-json", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument(
        "--expected-environment",
        default="release",
        choices=("release", "release-admin"),
        help="Expected environment name: release (package/draft) or release-admin (verifiers only).",
    )
    args = parser.parse_args(argv)
    try:
        result = verify(args.environment_json, args.policies_json, args.tag, args.expected_environment)
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
