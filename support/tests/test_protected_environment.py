#!/usr/bin/env python3
"""Offline tests for support/release/verify-protected-environment.py.

The .2 policy uses explicit owner self-approval: the owner reviewer is pinned
by immutable numeric GitHub id, prevent_self_review is false, admin bypass is
false, and the deployment policy is the exact tag with a verified pagination
total count. Temp files only; never touches the real tree, network, or
production runtime. Run with ``python3 -B``.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = SOURCE_ROOT / "support" / "release" / "verify-protected-environment.py"
TAG = "v0.1.0-testnet.4"


def load_module():
    spec = importlib.util.spec_from_file_location("protected_environment", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load verifier module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = load_module()


def make_environment(**overrides):
    env = {
        "name": "release",
        "environment": "release",
        "can_admins_bypass": False,
        "prevent_self_review": False,
        "protection_rules": [
            {
                "type": "required_reviewers",
                "reviewers": [
                    {"type": "User", "reviewer": {"login": "emyrinj", "id": 86115037}}
                ],
                "prevent_self_review": False,
            }
        ],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }
    env.update(overrides)
    return env


def make_policies(names=(TAG,), total_count=None):
    if total_count is None:
        total_count = len(names)
    return {
        "total_count": total_count,
        "branch_policies": [{"type": "tag", "name": name} for name in names],
    }


class ProtectedEnvironmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="astatine-prot-env-")
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, name: str, data: object) -> Path:
        path = self.root / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def verify(self, env_data: object, policies_data: object, tag: str = TAG) -> dict:
        env_path = self.write("env.json", env_data)
        pol_path = self.write("pol.json", policies_data)
        return MOD.verify(env_path, pol_path, tag)

    def test_valid_owner_self_approval_exact_tag(self) -> None:
        result = self.verify(make_environment(), make_policies())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["reviewer_rule_count"], 1)
        self.assertFalse(result["prevent_self_review"])
        self.assertTrue(result["owner_self_approval"])
        self.assertFalse(result["independent_review"])
        self.assertTrue(result["owner_reviewer_id_matched"])
        self.assertTrue(result["pagination_total_count_verified"])
        self.assertEqual(result["tag_policy_matched"], TAG)

    def test_real_github_environment_shape(self) -> None:
        env = {
            "id": 1,
            "name": "release",
            "can_admins_bypass": False,
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": False,
                    "reviewers": [
                        {"type": "User", "reviewer": {"login": "emyrinj", "id": 86115037}}
                    ],
                },
                {"type": "branch_policy"},
            ],
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        }
        result = self.verify(env, make_policies())
        self.assertEqual(result["status"], "PASS")

    def test_valid_top_level_prevent_self_review_false(self) -> None:
        env = make_environment(prevent_self_review=False)
        result = self.verify(env, make_policies())
        self.assertEqual(result["status"], "PASS")

    def test_missing_top_level_prevent_self_review_is_allowed_when_rule_false(self) -> None:
        env = make_environment()
        env.pop("prevent_self_review")
        result = self.verify(env, make_policies())
        self.assertEqual(result["status"], "PASS")

    def test_valid_policies_dict_shape(self) -> None:
        env_path = self.write("env.json", make_environment())
        pol_path = self.write("pol.json", make_policies())
        result = MOD.verify(env_path, pol_path, TAG)
        self.assertEqual(result["status"], "PASS")

    def test_valid_policies_key_shape_with_total_count(self) -> None:
        env_path = self.write("env.json", make_environment())
        pol_path = self.write(
            "pol.json",
            {"total_count": 1, "policies": [{"type": "tag", "name": TAG}]},
        )
        result = MOD.verify(env_path, pol_path, TAG)
        self.assertEqual(result["status"], "PASS")

    def test_reject_bare_list_policy_without_total_count(self) -> None:
        env_path = self.write("env.json", make_environment())
        pol_path = self.write("pol.json", [{"type": "tag", "name": TAG}])
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            MOD.verify(env_path, pol_path, TAG)

    def test_reject_missing_total_count(self) -> None:
        policies = {"branch_policies": [{"type": "tag", "name": TAG}]}
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), policies)

    def test_reject_ambiguous_policy_array_fields(self) -> None:
        policies = make_policies()
        policies["policies"] = [{"type": "tag", "name": TAG}]
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), policies)

    def test_reject_unexpected_policy_fields(self) -> None:
        policies = make_policies()
        policies["note"] = "extra"
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), policies)

    def test_reject_total_count_mismatch(self) -> None:
        policies = make_policies()
        policies["total_count"] = 2
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), policies)

    def test_reject_second_policy_hidden_by_pagination(self) -> None:
        policies = make_policies(total_count=2)
        policies["branch_policies"].append({"type": "tag", "name": "v*"})
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), policies)

    def test_reject_two_policies_even_with_correct_total_count(self) -> None:
        policies = make_policies(names=(TAG, TAG), total_count=2)
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), policies)

    def test_reject_pagination_total_over_bound(self) -> None:
        policies = {"total_count": 101, "branch_policies": [{"type": "tag", "name": TAG}]}
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), policies)

    def test_reject_overbroad_vstar(self) -> None:
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), make_policies(names=("v*",)))

    def test_reject_series_wildcard(self) -> None:
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), make_policies(names=("v0.1.0-testnet.*",)))

    def test_reject_other_exact_tag(self) -> None:
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), make_policies(names=("v0.1.0-testnet.1",)))

    def test_reject_star(self) -> None:
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), make_policies(names=("*",)))

    def test_reject_doublestar(self) -> None:
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), make_policies(names=("**",)))

    def test_reject_second_branch_policy(self) -> None:
        policies = {
            "total_count": 2,
            "branch_policies": [
                {"type": "tag", "name": TAG},
                {"type": "branch", "name": "main"},
            ],
        }
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), policies)

    def test_branch_only_fails(self) -> None:
        policies = {"total_count": 1, "branch_policies": [{"type": "branch", "name": "main"}]}
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), policies)

    def test_empty_policies_fail(self) -> None:
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), {"total_count": 0, "branch_policies": []})

    def test_missing_environment_name_fails(self) -> None:
        env = make_environment()
        del env["name"]
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_wrong_environment_name_fails(self) -> None:
        env = make_environment(name="other")
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_admin_bypass_true_fails(self) -> None:
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(can_admins_bypass=True), make_policies())

    def test_missing_reviewer_rule_fails(self) -> None:
        env = make_environment()
        env["protection_rules"] = [{"type": "other", "reviewers": []}]
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_two_reviewer_rules_fail(self) -> None:
        env = make_environment()
        env["protection_rules"] = [
            {
                "type": "required_reviewers",
                "reviewers": [{"type": "User", "reviewer": {"login": "emyrinj", "id": 86115037}}],
                "prevent_self_review": False,
            },
            {
                "type": "required_reviewers",
                "reviewers": [{"type": "User", "reviewer": {"login": "emyrinj", "id": 86115037}}],
                "prevent_self_review": False,
            },
        ]
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_empty_reviewers_fails(self) -> None:
        env = make_environment()
        env["protection_rules"][0]["reviewers"] = []
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_second_reviewer_fails(self) -> None:
        env = make_environment()
        env["protection_rules"][0]["reviewers"].append(
            {"type": "User", "reviewer": {"login": "other", "id": 1}}
        )
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_team_reviewer_fails(self) -> None:
        env = make_environment()
        env["protection_rules"][0]["reviewers"] = [
            {"type": "Team", "reviewer": {"slug": "release-reviewers", "id": 2}}
        ]
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_wrong_reviewer_id_fails(self) -> None:
        env = make_environment()
        env["protection_rules"][0]["reviewers"][0]["reviewer"]["id"] = 25130814
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_wrong_reviewer_login_fails(self) -> None:
        env = make_environment()
        env["protection_rules"][0]["reviewers"][0]["reviewer"]["login"] = "other-reviewer"
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_prevent_self_review_true_fails(self) -> None:
        env = make_environment()
        env["protection_rules"][0]["prevent_self_review"] = True
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_top_level_prevent_self_review_true_fails(self) -> None:
        env = make_environment(prevent_self_review=True)
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_missing_rule_prevent_self_review_fails(self) -> None:
        env = make_environment()
        env["protection_rules"][0].pop("prevent_self_review")
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_protected_branches_true_fails(self) -> None:
        env = make_environment()
        env["deployment_branch_policy"]["protected_branches"] = True
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_custom_branch_policies_false_fails(self) -> None:
        env = make_environment()
        env["deployment_branch_policy"] = {"custom_branch_policies": False}
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_wrong_tag_fails(self) -> None:
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), make_policies(names=(TAG,)), tag="v9.9.9-testnet.9")

    def test_malformed_environment_json_fails(self) -> None:
        env_path = self.root / "env.json"
        env_path.write_text("{not json", encoding="utf-8")
        pol_path = self.write("pol.json", make_policies())
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            MOD.verify(env_path, pol_path, TAG)

    def test_malformed_policies_json_fails(self) -> None:
        env_path = self.write("env.json", make_environment())
        pol_path = self.root / "pol.json"
        pol_path.write_text("[1,2,", encoding="utf-8")
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            MOD.verify(env_path, pol_path, TAG)

    def test_missing_file_fails(self) -> None:
        env_path = self.write("env.json", make_environment())
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            MOD.verify(env_path, self.root / "nope.json", TAG)

    def test_missing_field_fails(self) -> None:
        env = make_environment()
        del env["can_admins_bypass"]
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_reviewer_identities_never_printed(self) -> None:
        marker = "SECRET-REVIEWER-MARKER-xyz"
        env = make_environment()
        env["protection_rules"][0]["reviewers"] = [
            {"type": "User", "reviewer": {"login": marker, "id": 86115037}}
        ]
        env_path = self.write("env.json", env)
        pol_path = self.write("pol.json", make_policies())
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = MOD.main([
                "--environment-json", str(env_path),
                "--policies-json", str(pol_path),
                "--tag", TAG,
            ])
        self.assertEqual(code, 1)
        self.assertNotIn(marker, stdout.getvalue())
        self.assertNotIn(marker, stderr.getvalue())
        # Success output also withholds the owner login and numeric id.
        env = make_environment()
        env_path.write_text(json.dumps(env), encoding="utf-8")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = MOD.main([
                "--environment-json", str(env_path),
                "--policies-json", str(pol_path),
                "--tag", TAG,
            ])
        self.assertEqual(code, 0)
        self.assertNotIn("emyrinj", stdout.getvalue())
        self.assertNotIn("86115037", stdout.getvalue())
        self.assertNotIn("86115037", stderr.getvalue())

    def test_cli_exit_codes(self) -> None:
        env_path = self.write("env.json", make_environment())
        pol_path = self.write("pol.json", make_policies())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(MOD.main(["--environment-json", str(env_path), "--policies-json", str(pol_path), "--tag", TAG]), 0)
        bad = make_environment(can_admins_bypass=True)
        bad_path = self.write("bad.json", bad)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(MOD.main(["--environment-json", str(bad_path), "--policies-json", str(pol_path), "--tag", TAG]), 1)


if __name__ == "__main__":
    unittest.main()
