#!/usr/bin/env python3
"""Offline tests for support/release/verify-protected-environment.py.

Temp files only; never touches the real tree, network, or production
runtime. Run with ``python3 -B``.
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
from unittest import mock

SOURCE_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = SOURCE_ROOT / "support" / "release" / "verify-protected-environment.py"
TAG = "v0.1.0-testnet.1"


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
        "environment": "release",
        "can_admins_bypass": False,
        "prevent_self_review": False,
        "protection_rules": [
            {
                "type": "required_reviewers",
                "reviewers": [
                    {"type": "User", "reviewer": {"login": "owner", "id": 1}}
                ],
                "prevent_self_review": True,
            }
        ],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }
    env.update(overrides)
    return env


def make_policies(names=("v0.1.0-testnet.*",)):
    return {"branch_policies": [{"type": "tag", "name": name} for name in names]}


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

    def test_valid_series_rule_level(self) -> None:
        result = self.verify(make_environment(), make_policies())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["reviewer_rule_count"], 1)

    def test_real_github_environment_shape(self) -> None:
        env = {
            "id": 1,
            "name": "release",
            "can_admins_bypass": False,
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [
                        {"type": "User", "reviewer": {"login": "owner", "id": 1}},
                        {"type": "Team", "reviewer": {"slug": "release-reviewers", "id": 2}},
                    ],
                }
            ],
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        }
        result = self.verify(env, make_policies())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["reviewer_count"], 2)

    def test_valid_top_level_prevent_self_review(self) -> None:
        env = make_environment(prevent_self_review=True)
        env["protection_rules"][0].pop("prevent_self_review")
        result = self.verify(env, make_policies())
        self.assertEqual(result["status"], "PASS")

    def test_valid_exact_tag_policy(self) -> None:
        result = self.verify(make_environment(), make_policies(names=(TAG,)))
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["tag_policy_matched"], TAG)

    def test_valid_policies_list_shape(self) -> None:
        env_path = self.write("env.json", make_environment())
        pol_path = self.write("pol.json", [{"type": "tag", "name": "v0.1.0-testnet.*"}])
        result = MOD.verify(env_path, pol_path, TAG)
        self.assertEqual(result["status"], "PASS")

    def test_valid_policies_key_shape(self) -> None:
        env_path = self.write("env.json", make_environment())
        pol_path = self.write("pol.json", {"policies": [{"type": "tag", "name": TAG}]})
        result = MOD.verify(env_path, pol_path, TAG)
        self.assertEqual(result["status"], "PASS")

    def test_single_policy_count_reported(self) -> None:
        result = self.verify(make_environment(), make_policies())
        self.assertEqual(result["tag_policy_matched"], "v0.1.0-testnet.*")

    def test_reject_overbroad_vstar(self) -> None:
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), make_policies(names=("v*",)))

    def test_reject_overbroad_star(self) -> None:
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), make_policies(names=("*",)))

    def test_reject_overbroad_doublestar(self) -> None:
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), make_policies(names=("**",)))

    def test_safe_tag_plus_broad_vstar_fails(self) -> None:
        policies = {
            "branch_policies": [
                {"type": "tag", "name": "v0.1.0-testnet.*"},
                {"type": "tag", "name": "v*"},
            ]
        }
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), policies)

    def test_safe_tag_plus_branch_policy_fails(self) -> None:
        policies = {
            "branch_policies": [
                {"type": "tag", "name": "v0.1.0-testnet.*"},
                {"type": "branch", "name": "main"},
            ]
        }
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), policies)

    def test_safe_tag_plus_second_safe_tag_fails(self) -> None:
        policies = {
            "branch_policies": [
                {"type": "tag", "name": "v0.1.0-testnet.*"},
                {"type": "tag", "name": TAG},
            ]
        }
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), policies)

    def test_two_item_bare_list_fails(self) -> None:
        env_path = self.write("env.json", make_environment())
        pol_path = self.write(
            "pol.json",
            [
                {"type": "tag", "name": "v0.1.0-testnet.*"},
                {"type": "tag", "name": TAG},
            ],
        )
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            MOD.verify(env_path, pol_path, TAG)

    def test_branch_only_fails(self) -> None:
        policies = {"branch_policies": [{"type": "branch", "name": "main"}]}
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), policies)

    def test_empty_policies_fail(self) -> None:
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(), {"branch_policies": []})

    def test_admin_bypass_true_fails(self) -> None:
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(make_environment(can_admins_bypass=True), make_policies())

    def test_missing_reviewer_rule_fails(self) -> None:
        env = make_environment()
        env["protection_rules"] = [{"type": "other", "reviewers": ["x"]}]
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_two_reviewer_rules_fail(self) -> None:
        env = make_environment()
        env["protection_rules"] = [
            {"type": "required_reviewers", "reviewers": ["a"], "prevent_self_review": True},
            {"type": "required_reviewers", "reviewers": ["b"], "prevent_self_review": True},
        ]
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_empty_reviewers_fails(self) -> None:
        env = make_environment()
        env["protection_rules"][0]["reviewers"] = []
        with self.assertRaises(MOD.ProtectedEnvironmentError):
            self.verify(env, make_policies())

    def test_prevent_self_review_false_fails(self) -> None:
        env = make_environment()
        env["protection_rules"][0]["prevent_self_review"] = False
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
            self.verify(make_environment(), make_policies(names=("v0.1.0-testnet.1",)), tag="v9.9.9-testnet.9")

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
        env["protection_rules"][0]["reviewers"] = [marker]
        env_path = self.write("env.json", env)
        pol_path = self.write("pol.json", make_policies())
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = MOD.main([
                "--environment-json", str(env_path),
                "--policies-json", str(pol_path),
                "--tag", TAG,
            ])
        self.assertEqual(code, 0)
        self.assertNotIn(marker, stdout.getvalue())
        self.assertNotIn(marker, stderr.getvalue())
        # Failure output also withholds identities.
        env["protection_rules"][0]["reviewers"] = []
        env_path.write_text(json.dumps(env), encoding="utf-8")
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
