#!/usr/bin/env python3
"""Offline mutation tests for support/check_dependency_policy.py (E-02, E-07).

Every test copies the real repository files into a temporary directory and
mutates only that copy. No test touches the real source tree, the network,
cargo build/compile, wallets, or production runtime.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SOURCE_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = SOURCE_ROOT / "support" / "check_dependency_policy.py"

NEEDED_FILES = (
    "rust-toolchain.toml",
    "Cargo.toml",
    "Cargo.lock",
    "support/dependency-policy.md",
    ".github/workflows/ci.yml",
    ".github/workflows/linux-native-qualification.yml",
    ".github/workflows/linux-release-dry-run.yml",
)


def load_checker():
    spec = importlib.util.spec_from_file_location("dependency_policy_checker", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load check_dependency_policy.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()


class ToolchainAndDependencyPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="astatine-policy-test."))
        for relative in NEEDED_FILES:
            source = SOURCE_ROOT / relative
            target = self.tmp / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def mutate(self, relative: str, old: str, new: str) -> None:
        path = self.tmp / relative
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text, "expected fixture text %r in %s" % (old, relative))
        path.write_text(text.replace(old, new), encoding="utf-8")

    def check(self, root: Path | None = None) -> list:
        return CHECKER.run_static_checks(root if root is not None else self.tmp)

    def assertFailsWith(self, errors: list, fragment: str) -> None:
        self.assertTrue(errors, "expected check failure but got pass")
        joined = "\n".join(errors)
        self.assertIn(fragment, joined)

    def test_current_repo_passes_static_checks(self) -> None:
        self.assertEqual(CHECKER.run_static_checks(SOURCE_ROOT), [])
        self.assertEqual(self.check(), [])

    def test_floating_channel_fails(self) -> None:
        self.mutate("rust-toolchain.toml", 'channel = "1.94.1"', 'channel = "stable"')
        self.assertFailsWith(self.check(), "rust-toolchain.toml")

    def test_toolchain_version_drift_fails(self) -> None:
        self.mutate("rust-toolchain.toml", 'channel = "1.94.1"', 'channel = "1.93.0"')
        self.assertFailsWith(self.check(), "rust-toolchain.toml")

    def test_cargo_rust_version_mismatch_fails(self) -> None:
        self.mutate("Cargo.toml", 'rust-version = "1.94.1"', 'rust-version = "1.93.0"')
        self.assertFailsWith(self.check(), "Cargo.toml")

    def test_ci_toolchain_mismatch_fails(self) -> None:
        self.mutate(
            ".github/workflows/ci.yml",
            'RUSTUP_TOOLCHAIN: "1.94.1"',
            'RUSTUP_TOOLCHAIN: "1.93.0"',
        )
        self.assertFailsWith(self.check(), "ci.yml")

    def test_ci_missing_version_assertion_fails(self) -> None:
        self.mutate(
            ".github/workflows/ci.yml",
            '\n          test "$(rustc --version | awk \'{print $2}\')" = "1.94.1"\n',
            "\n",
        )
        self.assertFailsWith(self.check(), "ci.yml")

    def test_linux_workflow_pin_mismatch_fails(self) -> None:
        self.mutate(
            ".github/workflows/linux-native-qualification.yml",
            'RUSTUP_TOOLCHAIN: "1.94.1"',
            'RUSTUP_TOOLCHAIN: "1.95.0"',
        )
        self.assertFailsWith(
            self.check(), "linux-native-qualification.yml"
        )

    def test_release_dry_run_workflow_pin_mismatch_fails(self) -> None:
        self.mutate(
            ".github/workflows/linux-release-dry-run.yml",
            'RUSTUP_TOOLCHAIN: "1.94.1"',
            'RUSTUP_TOOLCHAIN: "1.95.0"',
        )
        self.assertFailsWith(
            self.check(), "linux-release-dry-run.yml"
        )

    def test_release_dry_run_workflow_install_mismatch_fails(self) -> None:
        self.mutate(
            ".github/workflows/linux-release-dry-run.yml",
            "rustup toolchain install 1.94.1",
            "rustup toolchain install 1.93.0",
        )
        self.assertFailsWith(
            self.check(), "linux-release-dry-run.yml"
        )

    def test_missing_advisory_text_fails(self) -> None:
        self.mutate(
            "support/dependency-policy.md", "RUSTSEC-2026-0387", "RUSTSEC-0000-0000"
        )
        self.assertFailsWith(self.check(), "RUSTSEC-2026-0387")

    def test_missing_patched_version_text_fails(self) -> None:
        self.mutate("support/dependency-policy.md", ">=0.7.6", "(patched line redacted)")
        self.assertFailsWith(self.check(), ">=0.7.6")

    def test_missing_removal_transition_text_fails(self) -> None:
        self.mutate(
            "support/dependency-policy.md", "must be removed", "may stay forever"
        )
        self.assertFailsWith(self.check(), "must be removed")

    def test_missing_exception_text_fails(self) -> None:
        text_path = self.tmp / "support" / "dependency-policy.md"
        text = text_path.read_text(encoding="utf-8")
        text_path.write_text(
            text.replace("exception", "exemption").replace("Exception", "Exemption"),
            encoding="utf-8",
        )
        self.assertFailsWith(self.check(), "exception")

    def test_missing_audit_ignore_fails(self) -> None:
        self.mutate(
            ".github/workflows/ci.yml",
            "cargo audit --ignore RUSTSEC-2026-0387",
            "cargo audit",
        )
        self.assertFailsWith(self.check(), "cargo audit --ignore")

    def test_missing_graph_guard_fails(self) -> None:
        self.mutate(
            ".github/workflows/ci.yml",
            "python3 support/check_dependency_policy.py --require-inactive",
            "echo no-guard",
        )
        self.assertFailsWith(self.check(), "inactive-graph guard")

    def remove_crypto_bigint_block(self, version: str) -> None:
        path = self.tmp / "Cargo.lock"
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        name_index = next(
            i
            for i, line in enumerate(lines)
            if line == 'name = "crypto-bigint"\n'
            and lines[i + 1] == 'version = "%s"\n' % version
        )
        start = name_index
        while lines[start] != "[[package]]\n":
            start -= 1
        end = name_index
        while lines[end] != "]\n":
            end += 1
        del lines[start : end + 1]
        path.write_text("".join(lines), encoding="utf-8")

    def remove_inactive_block(self) -> None:
        self.remove_crypto_bigint_block("0.5.5")

    def drop_audit_ignore(self) -> None:
        self.mutate(
            ".github/workflows/ci.yml",
            "run: cargo audit --ignore RUSTSEC-2026-0387",
            "run: cargo audit",
        )

    def cargo_result(self, returncode: int = 0, stdout: str = "") -> object:
        return subprocess.CompletedProcess(
            args=["cargo", "tree"], returncode=returncode, stdout=stdout
        )

    def test_absent_055_runs_positive_active_graph_check(self) -> None:
        self.remove_inactive_block()
        output = "crypto-bigint v0.7.9\ncrypto-bigint v0.7.9\n"
        with mock.patch(
            "subprocess.run", return_value=self.cargo_result(0, output)
        ) as run_mock:
            self.assertEqual(CHECKER.run_inactive_graph_check(self.tmp), [])
            invoked = run_mock.call_args.args[0]
            self.assertIn("--prefix", invoked)
            self.assertNotIn("-i", invoked)

    def test_positive_check_unpatched_active_version_fails(self) -> None:
        self.remove_inactive_block()
        output = "crypto-bigint v0.6.1\ncrypto-bigint v0.7.9\n"
        with mock.patch(
            "subprocess.run", return_value=self.cargo_result(0, output)
        ):
            errors = CHECKER.run_inactive_graph_check(self.tmp)
        self.assertFailsWith(errors, "v0.6.1")

    def test_positive_check_no_active_entries_passes(self) -> None:
        self.remove_inactive_block()
        with mock.patch(
            "subprocess.run", return_value=self.cargo_result(0, "")
        ) as run_mock:
            self.assertEqual(CHECKER.run_inactive_graph_check(self.tmp), [])
            run_mock.assert_called_once()

    def test_positive_check_command_error_fails(self) -> None:
        self.remove_inactive_block()
        output = "error: the lock file needs to be updated\n"
        with mock.patch(
            "subprocess.run", return_value=self.cargo_result(101, output)
        ):
            errors = CHECKER.run_inactive_graph_check(self.tmp)
        self.assertFailsWith(errors, "cargo tree exited 101")

    def test_positive_check_malformed_active_line_fails(self) -> None:
        self.remove_inactive_block()
        output = "crypto-bigint v0.7.9 unexpected-extra-token\n"
        with mock.patch(
            "subprocess.run", return_value=self.cargo_result(0, output)
        ):
            errors = CHECKER.run_inactive_graph_check(self.tmp)
        self.assertFailsWith(errors, "malformed active crypto-bigint")

    def test_positive_check_prerelease_is_not_treated_as_patched(self) -> None:
        self.remove_inactive_block()
        output = "crypto-bigint v0.7.6-alpha.1\n"
        with mock.patch(
            "subprocess.run", return_value=self.cargo_result(0, output)
        ):
            errors = CHECKER.run_inactive_graph_check(self.tmp)
        self.assertFailsWith(errors, "0.7.6-alpha.1")

    def test_inactive_graph_clean_tree_passes(self) -> None:
        with mock.patch(
            "subprocess.run",
            return_value=self.cargo_result(0, "warning: nothing to print.\n"),
        ) as run_mock:
            self.assertEqual(CHECKER.run_inactive_graph_check(self.tmp), [])
            run_mock.assert_called_once()

    def test_inactive_graph_package_in_active_graph_fails(self) -> None:
        output = "crypto-bigint v0.5.5\n└── ...\n"
        with mock.patch(
            "subprocess.run", return_value=self.cargo_result(0, output)
        ):
            errors = CHECKER.run_inactive_graph_check(self.tmp)
        self.assertFailsWith(errors, "crypto-bigint v0.5.5")

    def test_inactive_graph_cargo_error_fails(self) -> None:
        output = "error: package ID specification `crypto-bigint@0.5.5` did not match any packages\n"
        with mock.patch(
            "subprocess.run", return_value=self.cargo_result(101, output)
        ):
            errors = CHECKER.run_inactive_graph_check(self.tmp)
        self.assertFailsWith(errors, "cargo tree exited 101")

    def test_inactive_graph_os_error_fails(self) -> None:
        with mock.patch(
            "subprocess.run", side_effect=OSError("cargo not found")
        ):
            errors = CHECKER.run_inactive_graph_check(self.tmp)
        self.assertFailsWith(errors, "could not run cargo tree")

    def test_inactive_graph_os_error_withholds_absolute_path(self) -> None:
        with mock.patch(
            "subprocess.run",
            side_effect=OSError(2, "No such file or directory: '/tmp/astatine-secret-checkout'"),
        ):
            errors = CHECKER.run_inactive_graph_check(self.tmp)
        self.assertFailsWith(errors, "could not run cargo tree")
        self.assertNotIn("/tmp/astatine-secret-checkout", "\n".join(errors))
        self.assertNotIn("No such file", "\n".join(errors))

    def test_inactive_graph_timeout_fails(self) -> None:
        with mock.patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["cargo", "tree"], timeout=300),
        ):
            errors = CHECKER.run_inactive_graph_check(self.tmp)
        self.assertFailsWith(errors, "could not run cargo tree")

    def test_inactive_graph_timeout_withholds_command(self) -> None:
        with mock.patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(
                cmd=["cargo", "tree", "--locked", "/tmp/astatine-secret-checkout"], timeout=300
            ),
        ):
            errors = CHECKER.run_inactive_graph_check(self.tmp)
        self.assertFailsWith(errors, "could not run cargo tree")
        self.assertIn("timeout", "\n".join(errors))
        self.assertNotIn("/tmp/astatine-secret-checkout", "\n".join(errors))

    def test_duplicate_toolchain_channel_fails(self) -> None:
        path = self.tmp / "rust-toolchain.toml"
        with path.open("a", encoding="utf-8") as handle:
            handle.write('channel = "1.93.0"\n')
        self.assertFailsWith(self.check(), "rust-toolchain.toml")

    def test_toolchain_path_override_fails(self) -> None:
        path = self.tmp / "rust-toolchain.toml"
        with path.open("a", encoding="utf-8") as handle:
            handle.write('path = "/tmp/other-toolchain"\n')
        self.assertFailsWith(self.check(), "path =")

    def test_ci_duplicate_toolchain_env_fails(self) -> None:
        path = self.tmp / ".github" / "workflows" / "ci.yml"
        with path.open("a", encoding="utf-8") as handle:
            handle.write('\n  RUSTUP_TOOLCHAIN: "1.93.0"\n')
        self.assertFailsWith(self.check(), "ci.yml")

    def test_commented_audit_ignore_fails(self) -> None:
        self.mutate(
            ".github/workflows/ci.yml",
            "run: cargo audit --ignore RUSTSEC-2026-0387",
            "# run: cargo audit --ignore RUSTSEC-2026-0387",
        )
        self.assertFailsWith(self.check(), "cargo audit --ignore")

    def test_commented_guard_invocation_fails(self) -> None:
        self.mutate(
            ".github/workflows/ci.yml",
            "run: python3 support/check_dependency_policy.py --require-inactive",
            "# run: python3 support/check_dependency_policy.py --require-inactive",
        )
        self.assertFailsWith(self.check(), "inactive-graph guard")

    def test_disabled_guard_step_fails(self) -> None:
        self.mutate(
            ".github/workflows/ci.yml",
            "      - name: Keep inactive vulnerable optional package out of the active graph\n"
            "        run: python3 support/check_dependency_policy.py --require-inactive",
            "      - name: Keep inactive vulnerable optional package out of the active graph\n"
            "        if: false\n"
            "        run: python3 support/check_dependency_policy.py --require-inactive",
        )
        self.assertFailsWith(self.check(), "inactive-graph guard")

    def test_direct_crypto_bigint_dependency_fails(self) -> None:
        cargo_path = self.tmp / "Cargo.toml"
        with cargo_path.open("a", encoding="utf-8") as handle:
            handle.write('crypto-bigint = "=0.5.5"\n')
        self.assertFailsWith(self.check(), "direct crypto-bigint")

    def test_enabled_k256_reference_fails(self) -> None:
        cargo_path = self.tmp / "Cargo.toml"
        with cargo_path.open("a", encoding="utf-8") as handle:
            handle.write('k256 = "=0.13.4"\n')
        self.assertFailsWith(self.check(), "k256")

    def test_lockfile_absent_055_with_ignore_present_requires_removal(self) -> None:
        self.remove_inactive_block()
        self.assertFailsWith(self.check(), "must be removed")

    def test_cleared_state_passes_without_ignore(self) -> None:
        self.remove_inactive_block()
        self.drop_audit_ignore()
        self.assertEqual(self.check(), [])

    def test_zero_entries_clears_with_ignore_removed(self) -> None:
        self.remove_crypto_bigint_block("0.5.5")
        self.remove_crypto_bigint_block("0.7.9")
        self.drop_audit_ignore()
        self.assertEqual(self.check(), [])

    def test_lockfile_mixed_unpatched_without_exception_fails(self) -> None:
        self.mutate(
            "Cargo.lock",
            'name = "crypto-bigint"\nversion = "0.5.5"',
            'name = "crypto-bigint"\nversion = "0.6.1"',
        )
        self.assertFailsWith(self.check(), "0.6.1")

    def test_lockfile_newer_patched_release_passes(self) -> None:
        self.mutate(
            "Cargo.lock",
            'name = "crypto-bigint"\nversion = "0.7.9"',
            'name = "crypto-bigint"\nversion = "0.7.10"',
        )
        self.assertEqual(self.check(), [])

    def test_lockfile_unpatched_active_release_fails(self) -> None:
        self.mutate(
            "Cargo.lock",
            'name = "crypto-bigint"\nversion = "0.7.9"',
            'name = "crypto-bigint"\nversion = "0.7.5"',
        )
        self.assertFailsWith(self.check(), ">=0.7.6")

    def test_lockfile_prerelease_is_not_treated_as_patched(self) -> None:
        self.mutate(
            "Cargo.lock",
            'name = "crypto-bigint"\nversion = "0.7.9"',
            'name = "crypto-bigint"\nversion = "0.7.6-alpha.1"',
        )
        self.assertFailsWith(self.check(), "unparseable")


if __name__ == "__main__":
    unittest.main()
