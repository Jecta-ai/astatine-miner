#!/usr/bin/env python3
"""Offline regression checks for the disposable SSH qualification script.

These tests inspect source invariants only. They never create, modify, or delete
system accounts, never start sshd, and perform no network, wallet, Anvil, GPU,
or production-runtime operation.
"""

from __future__ import annotations

import pathlib
import unittest

SOURCE_ROOT = pathlib.Path(__file__).resolve().parents[2]
SSH_SCRIPT = SOURCE_ROOT / "support" / "linux" / "ssh-loopback-smoke.sh"


class SshLoopbackScriptInvariantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.script = SSH_SCRIPT.read_text(encoding="utf-8")
        self.lines = self.script.splitlines()

    def test_useradd_failure_never_marks_the_account_as_created(self) -> None:
        start = next(
            index
            for index, line in enumerate(self.lines)
            if line.strip().startswith("if ! sudo useradd")
        )
        end = next(
            index
            for index in range(start + 1, len(self.lines))
            if self.lines[index].strip() == "fi"
        )
        failure_block = "\n".join(self.lines[start : end + 1])
        self.assertNotIn(
            'created_user="true"',
            failure_block,
            "a failed useradd must never mark an account as created",
        )
        self.assertEqual(
            self.lines[end + 1].strip(),
            'created_user="true"',
            "created_user must be set only after the successful useradd block",
        )

    def test_cleanup_deletes_only_the_flagged_created_account(self) -> None:
        cleanup_start = next(
            index
            for index, line in enumerate(self.lines)
            if line.strip() == "cleanup() {"
        )
        cleanup_end = next(
            index
            for index in range(cleanup_start + 1, len(self.lines))
            if self.lines[index].strip() == "}"
        )
        cleanup_block = "\n".join(self.lines[cleanup_start : cleanup_end + 1])
        self.assertIn('[[ "$created_user" == "true" ]]', cleanup_block)
        self.assertIn("userdel -r", cleanup_block)

    def test_uses_random_username_and_fixed_trusted_sshd(self) -> None:
        self.assertIn('smoke_user="astatine-ssh-$(python3', self.script)
        self.assertIn('SSHD="/usr/sbin/sshd"', self.script)
        self.assertIn('sudo "$SSHD" -D', self.script)
        self.assertNotIn('sudo "$(command -v sshd)"', self.script)


if __name__ == "__main__":
    unittest.main()
