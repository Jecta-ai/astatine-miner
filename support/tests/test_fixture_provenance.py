#!/usr/bin/env python3
"""Safe offline tests for support/verify-fixture-provenance.py.

The tests copy the staged fixtures into a temporary directory and mutate only
that copy. They never touch the real source tree, network, wallet, Keychain,
Anvil, GPU or production runtime.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SOURCE_ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = Path(
    os.environ.get(
        "ASTATINE_VERIFIER_PATH",
        str(SOURCE_ROOT / "support" / "verify-fixture-provenance.py"),
    )
).resolve()
SCRUB_PATHS = [
    "README.md",
    "MACOS_ARM64.md",
    "src/protocol.rs",
    "support/update-evm-test-fixtures.py",
    "support/update-genesis-coordinator-fixture.py",
    "tests/fixtures/README.md",
]
INVENTORY_REL = Path("tests/fixtures/PROVENANCE.json")
FIXTURE_REL = Path("tests/fixtures/AstatineMiner.json")
FIXTURE_README_REL = Path("tests/fixtures/README.md")
LICENSE_REL = Path("tests/fixtures/OPENZEPPELIN_LICENSE.txt")


def load_verifier():
    spec = importlib.util.spec_from_file_location("fixture_provenance_verifier", VERIFIER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load verifier module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFIER = load_verifier()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


class FixtureProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="astatine-fixture-verify-")
        self.root = Path(self.tempdir.name)
        shutil.copytree(SOURCE_ROOT / "tests" / "fixtures", self.root / "tests" / "fixtures")
        for relative in SCRUB_PATHS:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(SOURCE_ROOT / relative, destination)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def inventory(self) -> dict:
        return json.loads((self.root / INVENTORY_REL).read_text(encoding="utf-8"))

    def write_inventory(self, inventory: dict) -> None:
        (self.root / INVENTORY_REL).write_text(
            json.dumps(inventory, indent=2) + "\n", encoding="utf-8"
        )

    def update_fixture_entry(self, inventory: dict, relative: Path, data: bytes) -> None:
        for entry in inventory["fixtures"]:
            if entry["path"] == relative.as_posix():
                entry["sha256"] = sha256_hex(data)
                entry["bytes"] = len(data)
                entry["canonical_git_blob_sha1"] = git_blob_sha1(data)
                return
        raise AssertionError(f"missing inventory entry for {relative}")

    def update_document_entry(self, inventory: dict, relative: Path, data: bytes) -> None:
        for document in inventory["documents"]:
            if document["path"] == relative.as_posix():
                document["sha256"] = sha256_hex(data)
                document["bytes"] = len(data)
                return
        raise AssertionError(f"missing document entry for {relative}")

    def test_real_inventory_passes(self) -> None:
        result = VERIFIER.verify(self.root)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["fixtures_checked"], 4)

    def test_tampered_fixture_bytes_fail(self) -> None:
        path = self.root / FIXTURE_REL
        document = json.loads(path.read_text(encoding="utf-8"))
        bytecode = document["bytecode"]["object"]
        document["bytecode"]["object"] = bytecode[:-1] + ("0" if bytecode[-1] != "0" else "1")
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "SHA-256 changed"):
            VERIFIER.verify(self.root)

    def test_source_pin_change_with_matching_hash_fails(self) -> None:
        path = self.root / FIXTURE_REL
        document = json.loads(path.read_text(encoding="utf-8"))
        document["source_commit"] = "0" * 40
        data = (json.dumps(document, indent=2) + "\n").encode()
        path.write_bytes(data)
        inventory = self.inventory()
        self.update_fixture_entry(inventory, FIXTURE_REL, data)
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "source pin changed"):
            VERIFIER.verify(self.root)

    def test_forbidden_abi_key_fails(self) -> None:
        path = self.root / FIXTURE_REL
        document = json.loads(path.read_text(encoding="utf-8"))
        document["abi"] = []
        data = (json.dumps(document, indent=2) + "\n").encode()
        path.write_bytes(data)
        inventory = self.inventory()
        self.update_fixture_entry(inventory, FIXTURE_REL, data)
        for entry in inventory["fixtures"]:
            if entry["path"] == FIXTURE_REL.as_posix():
                entry["json_keys"] = sorted(list(entry["json_keys"]) + ["abi"])
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "forbidden key abi"):
            VERIFIER.verify(self.root)

    def test_missing_openzeppelin_license_fails(self) -> None:
        (self.root / LICENSE_REL).unlink()
        with self.assertRaisesRegex(VERIFIER.VerificationError, "cannot read"):
            VERIFIER.verify(self.root)

    def test_private_origin_marker_in_readme_fails(self) -> None:
        marker = "fixture-test-owner/fixture-test-repo"
        path = self.root / FIXTURE_README_REL
        data = path.read_bytes() + f"\nleak: {marker}\n".encode()
        path.write_bytes(data)
        inventory = self.inventory()
        inventory["scrub_policy"]["prohibited_name_marker_sha256"].append(
            sha256_hex(marker.lower().encode())
        )
        self.update_document_entry(inventory, FIXTURE_README_REL, data)
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "private-origin marker"):
            VERIFIER.verify(self.root)

    def test_rights_status_cannot_be_upgraded(self) -> None:
        inventory = self.inventory()
        inventory["rights_review"]["rights_holder_authority"] = "ESTABLISHED"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "rights status must remain honest"):
            VERIFIER.verify(self.root)

    def test_owner_attestation_cannot_claim_independence_or_omit_fields(self) -> None:
        inventory = self.inventory()
        del inventory["rights_review"]["owner_attestation"]["independent_verification"]
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "owner_attestation"):
            VERIFIER.verify(self.root)

        inventory = self.inventory()
        inventory["rights_review"]["owner_attestation"]["independent_verification"] = True
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must not be represented as independent verification"
        ):
            VERIFIER.verify(self.root)

    def test_notice_checklist_cannot_be_emptied(self) -> None:
        inventory = self.inventory()
        inventory["rights_review"]["notice_checklist"]["items"] = []
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "notice_checklist items must not be empty"
        ):
            VERIFIER.verify(self.root)

    def test_blocked_publication_requires_an_open_blocking_item(self) -> None:
        inventory = self.inventory()
        for item in inventory["rights_review"]["notice_checklist"]["items"]:
            item["blocking"] = False
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "publication is BLOCKED but no blocking notice-checklist item is open",
        ):
            VERIFIER.verify(self.root)

    def test_synthetic_receipt_shape_is_pinned(self) -> None:
        receipt_rel = Path("tests/fixtures/synthetic-injective-virtual-receipt.json")
        path = self.root / receipt_rel
        document = json.loads(path.read_text(encoding="utf-8"))
        document["logs"] = [log for log in document["logs"] if not log.get("virtual")]
        data = (json.dumps(document, indent=2) + "\n").encode()
        path.write_bytes(data)
        inventory = self.inventory()
        self.update_fixture_entry(inventory, receipt_rel, data)
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "synthetic receipt log count changed"
        ):
            VERIFIER.verify(self.root)

    def test_fixture_identity_substitution_fails(self) -> None:
        inventory = self.inventory()
        inventory["fixtures"][3]["path"] = "tests/fixtures/AstatineMiner.json"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            r"fixtures\[3\] path substitution changes the expected fixture identity: "
            r"tests/fixtures/AstatineMiner\.json",
        ):
            VERIFIER.verify(self.root)

    def test_fixture_path_outside_expected_directory_fails(self) -> None:
        other_dir = self.root / "other"
        other_dir.mkdir()
        shutil.copy2(self.root / FIXTURE_REL, other_dir / FIXTURE_REL.name)
        inventory = self.inventory()
        inventory["fixtures"][0]["path"] = f"other/{FIXTURE_REL.name}"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            r"fixtures\[0\] path is not an expected fixture: other/AstatineMiner\.json",
        ):
            VERIFIER.verify(self.root)

    def test_fixture_path_traversal_fails(self) -> None:
        inventory = self.inventory()
        inventory["fixtures"][0]["path"] = "tests/fixtures/../fixtures/AstatineMiner.json"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "contains traversal"):
            VERIFIER.verify(self.root)

    def test_fixture_path_absolute_fails(self) -> None:
        inventory = self.inventory()
        inventory["fixtures"][0]["path"] = "/tmp/AstatineMiner.json"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "must not be absolute"):
            VERIFIER.verify(self.root)

    def test_fixture_file_symlink_fails(self) -> None:
        path = self.root / FIXTURE_REL
        target = self.root / "outside-AstatineMiner.json"
        shutil.copy2(path, target)
        path.unlink()
        os.symlink(target, path)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "symlink"):
            VERIFIER.verify(self.root)

    def test_directory_at_fixture_path_fails(self) -> None:
        path = self.root / FIXTURE_REL
        path.unlink()
        path.mkdir()
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            r"fixture JSON entry must be a regular file: AstatineMiner\.json",
        ):
            VERIFIER.verify(self.root)

    def test_document_symlink_fails(self) -> None:
        path = self.root / FIXTURE_README_REL
        target = self.root / "outside-README.md"
        shutil.copy2(path, target)
        path.unlink()
        os.symlink(target, path)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            r"fixture directory contains a symlink: README\.md",
        ):
            VERIFIER.verify(self.root)

    def test_legal_artifact_symlink_fails(self) -> None:
        path = self.root / LICENSE_REL
        target = self.root / "outside-OPENZEPPELIN_LICENSE.txt"
        shutil.copy2(path, target)
        path.unlink()
        os.symlink(target, path)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            r"fixture directory contains a symlink: OPENZEPPELIN_LICENSE\.txt",
        ):
            VERIFIER.verify(self.root)

    def test_parent_directory_symlink_fails(self) -> None:
        fixtures = self.root / "tests" / "fixtures"
        real = self.root / "tests" / "fixtures-real"
        fixtures.rename(real)
        os.symlink(real, fixtures)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "symlink component"):
            VERIFIER.verify(self.root)

    def test_document_path_traversal_fails(self) -> None:
        inventory = self.inventory()
        inventory["documents"][0]["path"] = "tests/fixtures/../fixtures/README.md"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "contains traversal"):
            VERIFIER.verify(self.root)

    def test_scrub_path_absolute_fails(self) -> None:
        inventory = self.inventory()
        inventory["scrub_policy"]["paths"][0] = "/tmp/README.md"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "must not be absolute"):
            VERIFIER.verify(self.root)

    def test_null_fixtures_list_fails(self) -> None:
        inventory = self.inventory()
        inventory["fixtures"] = None
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "fixtures must be a list"):
            VERIFIER.verify(self.root)

    def test_null_fixture_entry_fails(self) -> None:
        inventory = self.inventory()
        inventory["fixtures"][0] = None
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "fixtures\\[0\\] must be an object"):
            VERIFIER.verify(self.root)

    def test_null_openzeppelin_fails(self) -> None:
        inventory = self.inventory()
        inventory["openzeppelin"] = None
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "openzeppelin must be an object"):
            VERIFIER.verify(self.root)

    def test_null_document_entry_fails(self) -> None:
        inventory = self.inventory()
        inventory["documents"] = [None]
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "documents\\[0\\] must be an object"):
            VERIFIER.verify(self.root)

    def test_invalid_utf8_scrub_document_fails(self) -> None:
        (self.root / "README.md").write_bytes(b"\xff\xfe\x80invalid\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "not valid UTF-8"):
            VERIFIER.verify(self.root)

    def test_cli_schema_failure_returns_structured_json(self) -> None:
        inventory = self.inventory()
        inventory["fixtures"] = None
        self.write_inventory(inventory)
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", ["verify-fixture-provenance.py", str(self.root)]):
            with contextlib.redirect_stderr(stderr):
                return_code = VERIFIER.main()
        self.assertEqual(return_code, 1)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["status"], "FAIL")
        self.assertIn("fixtures must be a list", payload["error"])

    def test_scandir_oserror_returns_structured_json(self) -> None:
        denied = PermissionError(13, "Permission denied")
        stderr = io.StringIO()
        with mock.patch.object(VERIFIER.os, "scandir", side_effect=denied):
            with mock.patch.object(sys, "argv", ["verify-fixture-provenance.py", str(self.root)]):
                with contextlib.redirect_stderr(stderr):
                    return_code = VERIFIER.main()
        self.assertEqual(return_code, 1)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["status"], "FAIL")
        self.assertIn("cannot scan fixture directory tests/fixtures", payload["error"])

    def test_root_resolve_oserror_returns_structured_json(self) -> None:
        denied = PermissionError(13, "Permission denied")
        stderr = io.StringIO()
        with mock.patch.object(VERIFIER.Path, "resolve", side_effect=denied):
            with mock.patch.object(sys, "argv", ["verify-fixture-provenance.py", str(self.root)]):
                with contextlib.redirect_stderr(stderr):
                    return_code = VERIFIER.main()
        self.assertEqual(return_code, 1)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["status"], "FAIL")
        self.assertIn("source root is not readable", payload["error"])


if __name__ == "__main__":
    unittest.main()
