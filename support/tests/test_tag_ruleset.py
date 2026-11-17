#!/usr/bin/env python3
"""Offline tests for support/release/verify-tag-ruleset.py.

The .2 release requires two composable, exact-tag-scoped rulesets:

* ``astatine-release-tag-creation``: exactly the creation rule with one
  designated repository-admin bypass actor (creation protection is retained).
* ``astatine-release-tags``: exactly update/deletion/non-fast-forward with zero
  bypass actors.

Temp files only; no network or repository mutation. Run with ``python3 -B``.
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = SOURCE_ROOT / "support" / "release" / "verify-tag-ruleset.py"
TAG = "v0.1.0-testnet.2"
REPOSITORY = "Jecta-ai/astatine-miner"


def load_module():
    spec = importlib.util.spec_from_file_location("tag_ruleset_verifier", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load ruleset verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = load_module()


def make_creation(**overrides):
    data = {
        "id": 28000001,
        "name": "astatine-release-tag-creation",
        "target": "tag",
        "source_type": "Repository",
        "source": REPOSITORY,
        "enforcement": "active",
        "conditions": {"ref_name": {"include": [f"refs/tags/{TAG}"], "exclude": []}},
        "rules": [{"type": "creation"}],
        "bypass_actors": [
            {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}
        ],
    }
    data.update(overrides)
    return data


def make_immutability(**overrides):
    data = {
        "id": 28000002,
        "name": "astatine-release-tags",
        "target": "tag",
        "source_type": "Repository",
        "source": REPOSITORY,
        "enforcement": "active",
        "conditions": {
            "ref_name": {
                "include": [
                    "refs/tags/v0.1.0-testnet.0",
                    "refs/tags/v0.1.0-testnet.1",
                    f"refs/tags/{TAG}",
                ],
                "exclude": [],
            }
        },
        "rules": [
            {"type": "update"},
            {"type": "deletion"},
            {"type": "non_fast_forward"},
        ],
        "bypass_actors": [],
    }
    data.update(overrides)
    return data


class TagRulesetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="astatine-tag-ruleset-")
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def verify(self, creation: object, immutability: object) -> dict:
        return MOD.verify(creation, immutability, REPOSITORY, TAG)

    def test_valid_split_rulesets_pass(self) -> None:
        result = self.verify(make_creation(), make_immutability())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["creation_ruleset"]["rules"], ["creation"])
        self.assertEqual(result["creation_ruleset"]["bypass_actor_count"], 1)
        self.assertEqual(
            result["immutability_ruleset"]["rules"],
            ["deletion", "non_fast_forward", "update"],
        )
        self.assertEqual(result["immutability_ruleset"]["bypass_actor_count"], 0)

    def test_creation_exact_tag_scope_passes(self) -> None:
        creation = make_creation()
        creation["conditions"]["ref_name"]["include"] = [f"refs/tags/{TAG}"]
        self.assertEqual(
            self.verify(creation, make_immutability())["status"], "PASS"
        )

    def test_wrong_creation_name_fails(self) -> None:
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(make_creation(name="other"), make_immutability())

    def test_wrong_creation_target_fails(self) -> None:
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(make_creation(target="branch"), make_immutability())

    def test_wrong_creation_source_fails(self) -> None:
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(make_creation(source="Evil/fork"), make_immutability())

    def test_inactive_creation_fails(self) -> None:
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(make_creation(enforcement="evaluate"), make_immutability())

    def test_creation_missing_creation_rule_fails(self) -> None:
        creation = make_creation(rules=[])
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(creation, make_immutability())

    def test_creation_with_extra_rule_fails(self) -> None:
        creation = make_creation(rules=[{"type": "creation"}, {"type": "update"}])
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(creation, make_immutability())

    def test_creation_duplicate_rule_fails(self) -> None:
        creation = make_creation(rules=[{"type": "creation"}, {"type": "creation"}])
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(creation, make_immutability())

    def test_creation_broad_scope_fails(self) -> None:
        creation = make_creation()
        creation["conditions"]["ref_name"]["include"] = ["refs/tags/v*"]
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(creation, make_immutability())

    def test_creation_additional_scope_fails(self) -> None:
        creation = make_creation()
        creation["conditions"]["ref_name"]["include"] = [
            f"refs/tags/{TAG}",
            "refs/tags/v*",
        ]
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(creation, make_immutability())

    def test_creation_exclusion_fails(self) -> None:
        creation = make_creation()
        creation["conditions"]["ref_name"]["exclude"] = [f"refs/tags/{TAG}"]
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(creation, make_immutability())

    def test_creation_owner_user_bypass_passes(self) -> None:
        creation = make_creation(
            bypass_actors=[
                {"actor_id": 86115037, "actor_type": "User", "bypass_mode": "always"}
            ]
        )
        self.assertEqual(
            self.verify(creation, make_immutability())["status"], "PASS"
        )

    def test_creation_missing_bypass_fails(self) -> None:
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(make_creation(bypass_actors=[]), make_immutability())

    def test_creation_omitted_bypass_field_fails_closed(self) -> None:
        creation = make_creation()
        del creation["bypass_actors"]
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(creation, make_immutability())

    def test_creation_wrong_bypass_actor_fails(self) -> None:
        creation = make_creation(
            bypass_actors=[
                {"actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "always"}
            ]
        )
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(creation, make_immutability())

    def test_creation_wrong_bypass_mode_fails(self) -> None:
        creation = make_creation(
            bypass_actors=[
                {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request"}
            ]
        )
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(creation, make_immutability())

    def test_creation_extra_bypass_fails(self) -> None:
        creation = make_creation()
        creation["bypass_actors"].append(
            {"actor_id": 7, "actor_type": "Team", "bypass_mode": "always"}
        )
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(creation, make_immutability())

    def test_creation_current_user_bypass_never_passes(self) -> None:
        # current_user_can_bypass describes the calling identity, not the
        # configured bypass actor; the actor itself is validated separately.
        result = self.verify(
            make_creation(current_user_can_bypass="never"), make_immutability()
        )
        self.assertEqual(result["status"], "PASS")

    def test_creation_unexpected_caller_bypass_state_fails(self) -> None:
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(
                make_creation(current_user_can_bypass="unexpected"),
                make_immutability(),
            )

    def test_wrong_immutability_name_fails(self) -> None:
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(make_creation(), make_immutability(name="other"))

    def test_immutability_missing_update_fails(self) -> None:
        data = make_immutability()
        data["rules"] = [rule for rule in data["rules"] if rule["type"] != "update"]
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(make_creation(), data)

    def test_immutability_missing_deletion_fails(self) -> None:
        data = make_immutability()
        data["rules"] = [rule for rule in data["rules"] if rule["type"] != "deletion"]
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(make_creation(), data)

    def test_immutability_missing_non_fast_forward_fails(self) -> None:
        data = make_immutability()
        data["rules"] = [
            rule for rule in data["rules"] if rule["type"] != "non_fast_forward"
        ]
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(make_creation(), data)

    def test_immutability_creation_rule_fails(self) -> None:
        data = make_immutability()
        data["rules"].append({"type": "creation"})
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(make_creation(), data)

    def test_immutability_bypass_actor_fails(self) -> None:
        data = make_immutability(
            bypass_actors=[
                {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}
            ]
        )
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(make_creation(), data)

    def test_immutability_current_user_bypass_fails(self) -> None:
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(
                make_creation(), make_immutability(current_user_can_bypass="always")
            )

    def test_immutability_exact_tag_scope_only(self) -> None:
        data = make_immutability()
        data["conditions"]["ref_name"]["include"] = ["refs/tags/v*"]
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(make_creation(), data)

    def test_immutability_exact_2_only_scope_fails_historical_tags_unprotected(self) -> None:
        data = make_immutability()
        data["conditions"]["ref_name"]["include"] = [f"refs/tags/{TAG}"]
        with self.assertRaises(MOD.TagRulesetError):
            self.verify(make_creation(), data)

    def test_wrong_repository_argument_fails(self) -> None:
        with self.assertRaises(MOD.TagRulesetError):
            MOD.verify(make_creation(), make_immutability(), "Evil/fork", TAG)

    def test_wrong_tag_argument_fails(self) -> None:
        with self.assertRaises(MOD.TagRulesetError):
            MOD.verify(
                make_creation(), make_immutability(), REPOSITORY, "v0.1.0-testnet.1"
            )

    def test_malformed_json_fails(self) -> None:
        path = self.root / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(MOD.TagRulesetError):
            MOD.verify(MOD.load_json(path), make_immutability(), REPOSITORY, TAG)


if __name__ == "__main__":
    unittest.main()
