#!/usr/bin/env python3
"""Offline fail-closed validator for the split release-tag rulesets.

The protected tag policy uses two composable repository rulesets, each exactly
scoped to ``refs/tags/v*`` with no exclusions:

* ``astatine-release-tag-creation``: only the ``creation`` rule, with exactly
  the owner-user bypass actor (User 86115037, always) for owner-only creation
  covering all ``v*`` tags; repository-admin bypass is rejected.
* ``astatine-release-tags``: ``update``, ``deletion`` and ``non_fast_forward``
  with zero bypass actors, covering all ``refs/tags/v*`` tags so every version
  tag remains protected.

This preserves the breadth of the live tag protection, which restricts
creation/update/deletion for all ``refs/tags/v*``. Narrowing either ruleset
to the single ``v0.1.0-testnet.2`` tag, or to the historical
``v0.1.0-testnet.0``/``.1``/``.2`` list, weakens protection for all other
``v*`` tags and fails closed. Replacing the live ruleset with a narrowed
candidate would leave future ``v*`` tags unprotected and is rejected.

Creation protection is never removed. GitHub bypass actors are role/team/app/
user based; this validator accepts exactly the owner-user bypass actor:
the owner user (numeric id 86115037, always). Repository-admin bypass is
rejected and administrator bypass is disabled.
Admin-visible path (candidate under test): three sequenced
tag-ruleset-admin-verify workflow jobs each mint a short-lived App installation
token (pinned create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510
# v3.3.0 action, research-librarian independently re-verified via GitHub API
refs/tags/v3.3.0 at this SHA; action.yml declares app-id/client-id,
private-key required, owner/repositories optional, skip-token-revoke default
false, permission-administration input, token output, main+post entrypoints;
README states masked token, post-step revoke unless skip true, 1h expiry,
single-repo narrowing; ruleset docs fetch redirected to llms.txt so Metadata
minimum is NOT independently confirmed) for read-only ruleset GET with explicit
skip-token-revoke false and read-only GET (no -X/--method, no release/attest
mutations): the initial gate (needs preflight),
tag-ruleset-admin-verify-package sequenced via needs before release-package
(needs attest-macos, attest-linux, tag-ruleset-admin-verify), and
tag-ruleset-admin-verify-draft sequenced via needs before release-draft
(needs release-package); each runs in the dedicated release-admin environment
(owner sole self-approval User 86115037, prevent_self_review false,
can_admins_bypass false, exact tag v0.1.0-testnet.2) and re-verifies
release-admin live inline before mint, with App secrets only in those jobs.
Repository ruleset GET documents Metadata read minimum in some sources, plus
``bypass_actors`` is returned only when the caller has ruleset-write access;
whether the candidate App permission (permission-administration read) grants
it is UNPROVEN until owner-tested live runtime -- candidate under test,
verification needed, no write fallback. If read cannot access bypass_actors,
STOP: a later explicit write decision is required and must not be
auto-escalated here. This validator still fails closed on any snapshot without
``bypass_actors`` rather than treating it as an empty list, so default-token
snapshots without the field keep failing closed here; only the isolated admin
jobs (each itself fails closed if absent) are authoritative for the live bypass
check. Each admin job live-fetches the rulesets in its own run and verifies
GITHUB_REF/tag/repo-id live. Same-run needs does NOT automatically inherit SHA
binding; GITHUB_SHA trust is inherited from same-run preflight (HEAD==GITHUB_SHA
and tag peel==GITHUB_SHA verified via checkout) through the needs chain. Admin
jobs do no direct SHA equality check by design (no checkout while the App token
is live). Environment approvals can delay mutation after a check, so no check
is atomic or immediate; no stale signed snapshot is stored and manual
prepublish recheck still required. SHA pinning fixes
the mutable tag only, not inherent safety; third-party action risk (private key
and token handling, compromise impact) is described only as pin plus isolation
plus explicit revoke plus single-repo scope, without claiming elimination.
No stored token
or secret is added by this offline validator. Both snapshots must be
active and repository-scoped. Creation is exactly scoped to
``refs/tags/v*``; immutability is exactly scoped to ``refs/tags/v*`` with no
exclusions. Missing, extra, combined, broadened, narrowed, or bypassable
rulesets fail closed.

Usage:
    python3 -B support/release/verify-tag-ruleset.py \\
        --creation-ruleset-json <json> --immutability-ruleset-json <json> \\
        --repository Jecta-ai/astatine-miner --tag v0.1.0-testnet.2
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

EXPECTED_REPOSITORY = "Jecta-ai/astatine-miner"
EXPECTED_RELEASE_TAG = "v0.1.0-testnet.2"
# Both composable rulesets must preserve the live breadth: exactly
# refs/tags/v* with no exclusions. Narrowing to the single .2 tag or to the
# historical .0/.1/.2 list weakens protection for all other v* tags.
EXPECTED_TAG_SCOPE = ["refs/tags/v*"]
EXPECTED_CREATION_RULESET_NAME = "astatine-release-tag-creation"
EXPECTED_IMMUTABILITY_RULESET_NAME = "astatine-release-tags"
EXPECTED_CREATION_RULES = frozenset({"creation"})
EXPECTED_IMMUTABILITY_RULES = frozenset({"update", "deletion", "non_fast_forward"})
EXPECTED_CREATION_BYPASS_ACTOR = {
    "actor_id": 86115037,
    "actor_type": "User",
    "bypass_mode": "always",
}


class TagRulesetError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TagRulesetError(message)


def load_json(path: Path) -> object:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise TagRulesetError("cannot read ruleset JSON") from error
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TagRulesetError("ruleset JSON is malformed") from error


def _validate_common(
    data: object, expected_name: str, repository: str, expected_include: list[str]
) -> dict:
    require(isinstance(data, dict), "ruleset JSON must be an object")
    require(data.get("name") == expected_name, "ruleset name mismatch")
    require(data.get("target") == "tag", "ruleset target must be tag")
    require(data.get("source_type") == "Repository", "ruleset source_type must be Repository")
    require(data.get("source") == repository, "ruleset source must be the canonical repository")
    require(data.get("enforcement") == "active", "ruleset enforcement must be active")

    conditions = data.get("conditions")
    require(isinstance(conditions, dict), "ruleset conditions must be an object")
    ref_name = conditions.get("ref_name")
    require(isinstance(ref_name, dict), "ruleset conditions.ref_name must be an object")
    include = ref_name.get("include")
    exclude = ref_name.get("exclude")
    require(isinstance(include, list), "ruleset ref_name.include must be a list")
    require(isinstance(exclude, list), "ruleset ref_name.exclude must be a list")
    require(
        include == expected_include,
        "ruleset ref_name.include must be exactly [\"refs/tags/v*\"]; broader, narrower (including the single .2 tag or the historical .0/.1/.2 list), or additional scopes are rejected",
    )
    require(
        exclude == [],
        "ruleset ref_name.exclude must be empty; any exclusion broadens or removes protection",
    )
    return data


def _rule_types(data: dict) -> set[str]:
    rules = data.get("rules")
    require(isinstance(rules, list), "ruleset rules must be a list")
    rule_types: set[str] = set()
    for rule in rules:
        require(isinstance(rule, dict), "ruleset rule entries must be objects")
        rule_type = rule.get("type")
        require(isinstance(rule_type, str) and rule_type, "ruleset rule type must be a non-empty string")
        require(rule_type not in rule_types, "ruleset contains a duplicate rule type")
        rule_types.add(rule_type)
    return rule_types


def validate_creation_ruleset(data: object, repository: str, tag: str) -> dict:
    # ``tag`` Pins the release identity (verified in verify()); the ruleset
    # scope itself must remain the broad v* pattern to preserve live protection.
    require(tag == EXPECTED_RELEASE_TAG, "tag must be exactly the current release tag")
    data = _validate_common(data, EXPECTED_CREATION_RULESET_NAME, repository, list(EXPECTED_TAG_SCOPE))
    require(
        _rule_types(data) == EXPECTED_CREATION_RULES,
        "creation ruleset must contain exactly the creation rule; do not remove creation protection",
    )
    bypass = data.get("bypass_actors")
    require(
        isinstance(bypass, list),
        "creation ruleset bypass_actors must be present as a list; GitHub only returns it to callers with ruleset write access, and this snapshot did not provide it, so the creation bypass cannot be verified and the check fails closed",
    )
    require(
        len(bypass) == 1 and bypass[0] == EXPECTED_CREATION_BYPASS_ACTOR,
        "creation ruleset must have exactly the owner-user bypass actor (User 86115037, always); repository-admin bypass is rejected",
    )
    current_user_can_bypass = data.get("current_user_can_bypass")
    # ``current_user_can_bypass`` describes the calling identity, not the
    # configured bypass actor. The actor itself is validated above, so a
    # caller that personally cannot bypass ("never") is still safe.
    require(
        current_user_can_bypass in (None, "always", "exempt", "never"),
        "creation ruleset current_user_can_bypass has an unexpected value",
    )
    return {
        "ruleset_name": EXPECTED_CREATION_RULESET_NAME,
        "rules": sorted(EXPECTED_CREATION_RULES),
        "bypass_actor_count": 1,
        "tag_scope": EXPECTED_TAG_SCOPE[0],
    }


def validate_immutability_ruleset(data: object, repository: str, tag: str) -> dict:
    require(tag == EXPECTED_RELEASE_TAG, "tag must be exactly the current release tag")
    data = _validate_common(
        data,
        EXPECTED_IMMUTABILITY_RULESET_NAME,
        repository,
        list(EXPECTED_TAG_SCOPE),
    )
    rule_types = _rule_types(data)
    require(
        rule_types == EXPECTED_IMMUTABILITY_RULES,
        "immutability ruleset must contain exactly update, deletion and non_fast_forward; creation must live in the separate creation ruleset",
    )
    bypass = data.get("bypass_actors")
    require(isinstance(bypass, list), "immutability ruleset bypass_actors must be a list")
    require(
        not bypass,
        "immutability ruleset must not have bypass actors; administrator/repository-role bypass breaks tag immutability",
    )
    current_user_can_bypass = data.get("current_user_can_bypass")
    require(
        current_user_can_bypass not in ("always", "exempt"),
        "immutability ruleset must not allow the current user to bypass tag immutability",
    )
    return {
        "ruleset_name": EXPECTED_IMMUTABILITY_RULESET_NAME,
        "rules": sorted(EXPECTED_IMMUTABILITY_RULES),
        "bypass_actor_count": 0,
        "protected_tags": list(EXPECTED_TAG_SCOPE),
    }


def verify(creation_data: object, immutability_data: object, repository: str, tag: str) -> dict:
    require(repository == EXPECTED_REPOSITORY, "repository must be the canonical release repository")
    require(tag == EXPECTED_RELEASE_TAG, "tag must be exactly the current release tag")
    creation = validate_creation_ruleset(creation_data, repository, tag)
    immutability = validate_immutability_ruleset(immutability_data, repository, tag)
    return {
        "status": "PASS",
        "repository": repository,
        "tag": tag,
        "creation_ruleset": creation,
        "immutability_ruleset": immutability,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline validator for the split release-tag creation and immutability rulesets."
    )
    parser.add_argument("--creation-ruleset-json", required=True, type=Path)
    parser.add_argument("--immutability-ruleset-json", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args(argv)
    try:
        result = verify(
            load_json(args.creation_ruleset_json),
            load_json(args.immutability_ruleset_json),
            args.repository,
            args.tag,
        )
    except TagRulesetError as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}, indent=2), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"status": "FAIL", "error": "filesystem error"}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
