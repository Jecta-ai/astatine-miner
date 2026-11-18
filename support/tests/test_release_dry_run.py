#!/usr/bin/env python3
"""Offline regression tests for support/release/build-dry-run.py.

All tests use temporary directories for both the fake source tree and the
output directory. They never touch the real source tree, network, wallets,
builds, or publication paths. Run with `python3 -B` only.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SOURCE_ROOT = Path(__file__).resolve().parents[2]
DRY_RUN_PATH = SOURCE_ROOT / "support" / "release" / "build-dry-run.py"
WORKFLOW_PATH = SOURCE_ROOT / ".github" / "workflows" / "linux-release-dry-run.yml"

try:
    import yaml as _yaml
except ImportError:
    _yaml = None

PUBLICATION_DECISION = (
    "BLOCKED pending review of rights and notice applicability; "
    "first-party ownership is owner-attested and not independently verified."
)
ATTESTED_RIGHTS = "OWNER-ATTESTED \u2014 not independently verified"
TEST_BRANCH_PUSH_AUTHORIZATION = {
    "status": "AUTHORIZED \u2014 REVIEW/CI ONLY",
    "authorized_by": "project owner",
    "authorized_on": "2026-11-16",
    "scope": "Push the fix/phase-e-e02-e07 remediation branch to the already-public repository solely for review and CI.",
    "public_repository_visibility": "The repository is already public. That visibility does not authorize a source archive, binary archive or release, tag or release publication, or workflow attestation dispatch.",
    "not_authorized": [
        "source archive distribution",
        "binary archive or release distribution",
        "tag or public release publication",
        "workflow attestation dispatch",
        "broader license grant or legal clearance",
        "resolution of RIGHTS-02 through RIGHTS-05",
    ],
    "rights_gate_unchanged": "RIGHTS-02 through RIGHTS-05 remain OPEN and blocking; source_distribution and binary_distribution remain BLOCKED.",
}
BLOCKING_OPEN = ["RIGHTS-02", "RIGHTS-03", "RIGHTS-04", "RIGHTS-05"]
FIXTURE_PATHS = [
    "tests/fixtures/AstatineMiner.json",
    "tests/fixtures/AstatineGenesisCoordinator.json",
    "tests/fixtures/MockAST.json",
    "tests/fixtures/synthetic-injective-virtual-receipt.json",
]
EXPECTED_MEMBERS = ["BUILD-INFO.json", "INSTALL.md", "LICENSE-MIT", "THIRD_PARTY_LICENSES.md", "astatine"]
LEGIT_RUSTC_LINE = "rustc 1.94.1 (e408947bf 2026-03-25)"
LEGIT_CARGO_LINE = "cargo 1.94.1 (29ea6fb6a 2026-03-24)"
TEST_LOCK_BYTES = b"# test lock\n"
TEST_CARGO_TOML = (
    '[package]\n'
    'name = "astatine-cli-rust"\n'
    'version = "0.1.0-testnet.0"\n'
    'edition = "2024"\n'
)
TEST_REPOSITORY = "Jecta-ai/astatine-miner\n"
# Minimal valid ELF64 little-endian x86-64 header (e_type=EXEC, e_machine=62).
FAKE_ELF_BINARY = (
    b"\x7fELF"
    + bytes([2, 1, 1, 0])
    + bytes(8)
    + (2).to_bytes(2, "little")
    + (62).to_bytes(2, "little")
    + (1).to_bytes(4, "little")
    + bytes(40)
)
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


def load_dry_run():
    spec = importlib.util.spec_from_file_location("release_dry_run", DRY_RUN_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load build-dry-run module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DRY_RUN = load_dry_run()


def blocking_item(item_id: str) -> dict:
    expected = DRY_RUN.EXPECTED_BLOCKING_ITEMS[item_id]
    return {
        "id": item_id,
        "action": expected["action"],
        "owner": expected["owner"],
        "status": "OPEN",
        "blocking": True,
        "evidence": expected["evidence"],
    }


def make_provenance() -> dict:
    return {
        "schema": "astatine-fixture-provenance/v1",
        "rights_review": {
            "publication_decision": PUBLICATION_DECISION,
            "notice_applicability": "UNRESOLVED",
            "rights_holder_authority": ATTESTED_RIGHTS,
            "review_ci_branch_push_authorization": copy.deepcopy(TEST_BRANCH_PUSH_AUTHORIZATION),
            "owner_attestation": {
                "status": ATTESTED_RIGHTS,
                "independent_verification": False,
            },
            "notice_checklist": {
                "status": "OPEN \u2014 publication remains BLOCKED",
                "scope": "test scope",
                "items": [
                    {
                        "id": "RIGHTS-01",
                        "action": "test first-party ownership confirmation",
                        "owner": "project owner",
                        "status": "DONE",
                        "blocking": True,
                        "evidence": "test evidence",
                    },
                    blocking_item("RIGHTS-02"),
                    blocking_item("RIGHTS-03"),
                    blocking_item("RIGHTS-04"),
                    blocking_item("RIGHTS-05"),
                ],
            },
        },
        "fixtures": [
            {"path": path, "release_archive_member": False} for path in FIXTURE_PATHS
        ],
    }


def make_inventory() -> dict:
    return {
        "schema": "astatine-distribution-inventory/v1",
        "scope": "test scope",
        "rights_gate": {
            "source": "tests/fixtures/PROVENANCE.json",
            "publication_decision": PUBLICATION_DECISION,
            "notice_applicability": "UNRESOLVED",
            "blocking_open": list(BLOCKING_OPEN),
            "fail_closed": True,
            "rule": "test rule",
            "review_ci_branch_push_authorization": copy.deepcopy(TEST_BRANCH_PUSH_AUTHORIZATION),
        },
        "source_distribution": {"status": "BLOCKED", "reason": "test reason"},
        "binary_distribution": {
            "status": "BLOCKED",
            "reason": "test reason",
            "target": "x86_64-unknown-linux-gnu",
            "archive_members": [
                {"source": "target/release/astatine", "archive_path": "astatine", "required": True},
                {"source": "LICENSE-MIT", "archive_path": "LICENSE-MIT", "required": True},
                {
                    "source": "THIRD_PARTY_LICENSES.md",
                    "archive_path": "THIRD_PARTY_LICENSES.md",
                    "required": True,
                },
            ],
            "generated_members": [
                {
                    "archive_path": "BUILD-INFO.json",
                    "generator": "support/release/build-dry-run.py",
                    "required": True,
                },
                {
                    "archive_path": "INSTALL.md",
                    "generator": "support/release/build-dry-run.py",
                    "required": True,
                },
            ],
            "forbidden_globs": ["tests/fixtures/**", "**/PROVENANCE.json"],
            "fixture_paths": list(FIXTURE_PATHS),
        },
    }


def init_git_repo(root: Path) -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "dry-run-test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "dry-run-test"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "test gate"], check=True)


PUBLISH_VALUE_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bcargo\s+publish\b",
        r"\bnpm\s+publish\b",
        r"\bdocker\s+push\b",
        r"\bgit\s+push\b",
        r"\bgh\s+release\b",
        r"\bgh\s+api\b[^\n]*releases\b",
        r"\btwine\s+upload\b",
    )
)


def assert_workflow_structure(parsed: dict) -> None:
    """Parsed-YAML structural invariants for the dry-run workflow.

    The dry-run performs no attestation dispatch per the blocked distribution
    inventory: job permissions are contents: read only, and no attestation
    step or OIDC grant may exist.
    """
    raw_on = parsed.get(True, parsed.get("on"))
    if not isinstance(raw_on, dict):
        raise AssertionError(f"'on' must be a mapping, got: {raw_on!r}")
    if set(raw_on) != {"workflow_dispatch"}:
        raise AssertionError(f"'on' keys must be exactly workflow_dispatch, got: {sorted(raw_on)}")
    jobs = parsed.get("jobs")
    if not isinstance(jobs, dict) or "linux-release-dry-run" not in jobs:
        raise AssertionError("expected exactly the linux-release-dry-run job")
    job = jobs["linux-release-dry-run"]
    expected_permissions = {"contents": "read"}
    if job.get("permissions") != expected_permissions:
        raise AssertionError(f"job permissions must be exactly {expected_permissions}")
    for step in job.get("steps", []):
        text = str(step.get("run", "")) + str(step.get("uses", ""))
        if "attestation" in text.lower():
            raise AssertionError("dry-run workflow must not attest")
        if "attest-build-provenance" in text:
            raise AssertionError("dry-run workflow must not use attest-build-provenance")
        if "id-token: write" in text or "attestations: write" in text:
            raise AssertionError("dry-run workflow must not grant write permissions in steps")

    def walk(node: object, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                location = f"{path}.{key}"
                if key == "environment":
                    raise AssertionError(f"forbidden environment key at {location}")
                if isinstance(value, str):
                    for pattern in PUBLISH_VALUE_PATTERNS:
                        if pattern.search(value):
                            raise AssertionError(
                                f"forbidden publish command at {location}: {pattern.pattern}"
                            )
                walk(value, location)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")

    walk(parsed, "$")


class DryRunBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source_tmp = tempfile.TemporaryDirectory(prefix="astatine-dryrun-src-")
        self.out_tmp = tempfile.TemporaryDirectory(prefix="astatine-dryrun-out-")
        self.root = Path(self.source_tmp.name)
        self.out = Path(self.out_tmp.name) / "out"
        self.toolchain_patch = mock.patch.object(
            DRY_RUN, "observed_toolchain", return_value=LEGIT_RUSTC_LINE
        )
        self.toolchain_patch.start()
        self.cargo_patch = mock.patch.object(
            DRY_RUN, "observed_cargo_version", return_value=LEGIT_CARGO_LINE
        )
        self.cargo_patch.start()
        self.write_tree(make_provenance(), make_inventory())
        (self.root / ".gitignore").write_text("target/\n", encoding="utf-8")
        init_git_repo(self.root)

    def tearDown(self) -> None:
        self.cargo_patch.stop()
        self.toolchain_patch.stop()
        self.source_tmp.cleanup()
        self.out_tmp.cleanup()

    def write_tree(self, provenance: dict, inventory: dict) -> None:
        (self.root / "tests" / "fixtures").mkdir(parents=True, exist_ok=True)
        (self.root / "support" / "release").mkdir(parents=True, exist_ok=True)
        (self.root / "target" / "release").mkdir(parents=True, exist_ok=True)
        (self.root / "tests" / "fixtures" / "PROVENANCE.json").write_text(
            json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
        )
        (self.root / "support" / "release" / "distribution-inventory.json").write_text(
            json.dumps(inventory, indent=2) + "\n", encoding="utf-8"
        )
        (self.root / "target" / "release" / "astatine").write_bytes(FAKE_ELF_BINARY)
        (self.root / "LICENSE-MIT").write_text("test MIT\n", encoding="utf-8")
        (self.root / "THIRD_PARTY_LICENSES.md").write_text("test notices\n", encoding="utf-8")
        (self.root / "Cargo.toml").write_text(TEST_CARGO_TOML, encoding="utf-8")
        (self.root / "Cargo.lock").write_bytes(TEST_LOCK_BYTES)
        (self.root / "support" / "release-repository.txt").write_text(TEST_REPOSITORY, encoding="utf-8")

    def read_tree(self) -> tuple[dict, dict]:
        provenance = json.loads(
            (self.root / "tests" / "fixtures" / "PROVENANCE.json").read_text(encoding="utf-8")
        )
        inventory = json.loads(
            (self.root / "support" / "release" / "distribution-inventory.json").read_text(
                encoding="utf-8"
            )
        )
        return provenance, inventory

    def run_dry_run(self, **overrides):
        kwargs = {"source_root": self.root, "output_dir": self.out, "mode": "dry-run"}
        kwargs.update(overrides)
        return DRY_RUN.run(**kwargs)

    def test_builds_allowlisted_archive(self) -> None:
        result = self.run_dry_run()
        self.assertEqual(result["members"], EXPECTED_MEMBERS)
        self.assertFalse(result["publication_authorized"])
        self.assertEqual(result["publication_decision"], PUBLICATION_DECISION)
        self.assertEqual(result["notice_applicability"], "UNRESOLVED")
        self.assertEqual(result["blocking_open"], BLOCKING_OPEN)
        artifact = Path(result["artifact_path"])
        self.assertTrue(artifact.is_file())
        with tarfile.open(artifact, mode="r") as tar:
            names = sorted(tar.getnames())
        self.assertEqual(names, EXPECTED_MEMBERS)
        for name in names:
            self.assertNotIn("fixtures", name)
            self.assertNotIn("PROVENANCE", name)

    def test_generated_members_content(self) -> None:
        result = self.run_dry_run()
        record = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        with tarfile.open(result["artifact_path"], mode="r") as tar:
            build_info = json.loads(tar.extractfile("BUILD-INFO.json").read().decode("utf-8"))
            install = tar.extractfile("INSTALL.md").read().decode("utf-8")
        self.assertEqual(build_info["schema"], "astatine-build-info/v1")
        self.assertEqual(build_info["distribution"], "dry-run-no-publication")
        self.assertIs(build_info["publication_authorized"], False)
        self.assertEqual(build_info["package"], {"name": "astatine-cli-rust", "version": "0.1.0-testnet.0", "binary": "astatine"})
        self.assertEqual(build_info["target"], "x86_64-unknown-linux-gnu")
        self.assertEqual(build_info["profile"], "release")
        self.assertEqual(build_info["source"]["repository"], "Jecta-ai/astatine-miner")
        self.assertEqual(build_info["source"]["commit"], record["commit"])
        self.assertEqual(build_info["source"]["tree"], record["tree"])
        self.assertIn("T", build_info["source"]["source_date_utc"])
        self.assertIs(build_info["source"]["source_root_included"], False)
        self.assertEqual(build_info["build"]["command"], "cargo build --locked --release")
        self.assertIs(build_info["build"]["command_is_documented"], True)
        self.assertIs(build_info["build"]["verified_by_this_script"], False)
        self.assertEqual(build_info["build"]["rustc_version"], LEGIT_RUSTC_LINE)
        self.assertEqual(build_info["build"]["cargo_version"], LEGIT_CARGO_LINE)
        self.assertEqual(build_info["build"]["cargo_lock_sha256"], record["cargo_lock_sha256"])
        self.assertIn("git clone https://github.com/Jecta-ai/astatine-miner.git && git checkout", build_info["corresponding_source"]["how_to_obtain"])
        self.assertIs(build_info["corresponding_source"]["included_in_archive"], False)
        self.assertEqual(build_info["dependencies"]["lockfile_sha256"], record["cargo_lock_sha256"])
        self.assertEqual(build_info["dependencies"]["third_party_notices"], "THIRD_PARTY_LICENSES.md")
        self.assertEqual(build_info["dependencies"]["license"], "LICENSE-MIT")
        self.assertEqual(build_info["install"]["instructions"], "INSTALL.md")
        self.assertIn("unverified", build_info["build_linkage"])
        self.assertEqual(build_info["rights_gate"]["publication_decision"], PUBLICATION_DECISION)
        self.assertEqual(build_info["rights_gate"]["blocking_open"], BLOCKING_OPEN)
        self.assertEqual(
            build_info["rights_gate"]["review_ci_branch_push_authorization"]["status"],
            "AUTHORIZED — REVIEW/CI ONLY",
        )
        for marker in (
            "NOT FOR PUBLICATION",
            "0.1.0-testnet.0",
            "astatine-cli-rust",
            "x86_64-unknown-linux-gnu",
            "SHA256SUMS",
            "0755",
            "keep",
            "git clone https://github.com/Jecta-ai/astatine-miner.git",
            "unverified",
            "XDG_CONFIG_HOME",
            "~/Library/Application Support/Astatine",
            "%APPDATA%\\Astatine",
            "Never overwrite, delete",
        ):
            self.assertIn(marker, install)
        self.assertNotIn("publication_authorized\": true", json.dumps(build_info))

    def test_generated_bytes_have_no_wall_clock(self) -> None:
        first = self.run_dry_run()
        with tarfile.open(first["artifact_path"], mode="r") as tar:
            first_info = tar.extractfile("BUILD-INFO.json").read()
            first_install = tar.extractfile("INSTALL.md").read()
        import time as _time

        _time.sleep(1.1)
        second_out = Path(self.out_tmp.name) / "out-two"
        DRY_RUN.run(source_root=self.root, output_dir=second_out, mode="dry-run")
        second_artifact = second_out / "astatine-x86_64-unknown-linux-gnu.dry-run.tar.gz"
        with tarfile.open(second_artifact, mode="r") as tar:
            self.assertEqual(tar.extractfile("BUILD-INFO.json").read(), first_info)
            self.assertEqual(tar.extractfile("INSTALL.md").read(), first_install)

    def test_generated_hashes_match_provenance(self) -> None:
        result = self.run_dry_run()
        record = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        generated = {m["archive_path"]: m for m in record["artifact"]["members"] if m.get("generated")}
        self.assertEqual(sorted(generated), ["BUILD-INFO.json", "INSTALL.md"])
        for archive_path, entry in generated.items():
            self.assertEqual(entry["source"], f"generated:{archive_path}")
            self.assertEqual(entry["mode"], "0o644")
            self.assertEqual(entry["generator"], "support/release/build-dry-run.py")
        self.assertEqual(
            {m["archive_path"]: m["sha256"] for m in record["artifact"]["members"]},
            result["member_hashes"],
        )

    def test_missing_generated_contract_member_fails(self) -> None:
        provenance, inventory = self.read_tree()
        inventory["binary_distribution"]["generated_members"] = [
            {
                "archive_path": "BUILD-INFO.json",
                "generator": "support/release/build-dry-run.py",
                "required": True,
            }
        ]
        self.write_tree(provenance, inventory)
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-q", "-m", "tamper gate"], check=True)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "generated_members changed"):
            self.run_dry_run()

    def test_missing_generated_members_field_fails(self) -> None:
        provenance, inventory = self.read_tree()
        del inventory["binary_distribution"]["generated_members"]
        self.write_tree(provenance, inventory)
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-q", "-m", "tamper gate"], check=True)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "generated_members"):
            self.run_dry_run()

    def test_reordered_generated_members_fails(self) -> None:
        provenance, inventory = self.read_tree()
        inventory["binary_distribution"]["generated_members"] = list(
            reversed(inventory["binary_distribution"]["generated_members"])
        )
        self.write_tree(provenance, inventory)
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-q", "-m", "tamper gate"], check=True)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "generated_members changed"):
            self.run_dry_run()

    def test_injected_generated_member_fails(self) -> None:
        provenance, inventory = self.read_tree()
        inventory["binary_distribution"]["generated_members"] = [
            {
                "archive_path": "BUILD-INFO.json",
                "generator": "support/release/build-dry-run.py",
                "required": True,
            },
            {
                "archive_path": "INSTALL.md",
                "generator": "support/release/build-dry-run.py",
                "required": True,
            },
            {
                "archive_path": "EXTRA.md",
                "generator": "support/release/build-dry-run.py",
                "required": True,
            },
        ]
        self.write_tree(provenance, inventory)
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-q", "-m", "tamper gate"], check=True)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "generated_members changed"):
            self.run_dry_run()

    def test_fixture_generated_member_fails(self) -> None:
        provenance, inventory = self.read_tree()
        inventory["binary_distribution"]["generated_members"] = [
            {
                "archive_path": "BUILD-INFO.json",
                "generator": "support/release/build-dry-run.py",
                "required": True,
            },
            {
                "archive_path": "tests/fixtures/AstatineMiner.json",
                "generator": "support/release/build-dry-run.py",
                "required": True,
            },
        ]
        self.write_tree(provenance, inventory)
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-q", "-m", "tamper gate"], check=True)
        with self.assertRaises(DRY_RUN.DryRunError):
            self.run_dry_run()

    def test_canonical_paths_recorded_and_no_overrides(self) -> None:
        parameters = inspect.signature(DRY_RUN.run).parameters
        self.assertNotIn("provenance_rel", parameters)
        self.assertNotIn("inventory_rel", parameters)
        with self.assertRaises(SystemExit) as context:
            DRY_RUN.main(
                [
                    "--mode",
                    "dry-run",
                    "--output-dir",
                    str(self.out),
                    "--provenance-rel",
                    "tests/fixtures/PROVENANCE.json",
                ]
            )
        self.assertEqual(context.exception.code, 2)
        result = self.run_dry_run()
        record = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        self.assertNotIn("source_root", record)
        self.assertNotIn("invocation", record)
        self.assertEqual(record["provenance_path"], "tests/fixtures/PROVENANCE.json")
        self.assertEqual(record["inventory_path"], "support/release/distribution-inventory.json")

    def test_deterministic_bytes_across_runs(self) -> None:
        first = self.run_dry_run()
        first_bytes = Path(first["artifact_path"]).read_bytes()
        second_out = Path(self.out_tmp.name) / "out-two"
        second = DRY_RUN.run(source_root=self.root, output_dir=second_out, mode="dry-run")
        second_bytes = Path(second["artifact_path"]).read_bytes()
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(first["artifact_sha256"], second["artifact_sha256"])
        self.assertEqual(first["artifact_sha256"], hashlib.sha256(first_bytes).hexdigest())
        with tarfile.open(fileobj=io.BytesIO(first_bytes), mode="r") as tar:
            for member in tar.getmembers():
                self.assertEqual(member.mtime, 0)
                self.assertEqual(member.uid, 0)
                self.assertEqual(member.gid, 0)
                self.assertEqual(member.uname, "")
                self.assertEqual(member.gname, "")
        raw_gzip_mtime = first_bytes[4:8]
        self.assertEqual(raw_gzip_mtime, b"\x00\x00\x00\x00")

    def test_source_tree_is_not_modified(self) -> None:
        before: dict[str, bytes] = {}
        for path in sorted(self.root.rglob("*")):
            if ".git" in path.parts:
                continue
            if path.is_file() and not path.is_symlink():
                before[str(path.relative_to(self.root))] = path.read_bytes()
        self.run_dry_run()
        after: dict[str, bytes] = {}
        for path in sorted(self.root.rglob("*")):
            if ".git" in path.parts:
                continue
            if path.is_file() and not path.is_symlink():
                after[str(path.relative_to(self.root))] = path.read_bytes()
        self.assertEqual(before, after)

    def test_gate_mismatch_fails(self) -> None:
        provenance, inventory = self.read_tree()
        inventory["rights_gate"]["publication_decision"] = "BLOCKED with a local edit"
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "does not match"):
            self.run_dry_run()

    def test_prefixed_but_not_canonical_decision_fails(self) -> None:
        provenance, inventory = self.read_tree()
        edited = "BLOCKED but approved for test publication"
        provenance["rights_review"]["publication_decision"] = edited
        inventory["rights_gate"]["publication_decision"] = edited
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "publication decision changed"):
            self.run_dry_run()

    def test_unblocked_gate_fails(self) -> None:
        provenance, inventory = self.read_tree()
        provenance["rights_review"]["publication_decision"] = "APPROVED for test"
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "publication decision changed"):
            self.run_dry_run()

    def test_checklist_status_rewording_fails(self) -> None:
        provenance, inventory = self.read_tree()
        provenance["rights_review"]["notice_checklist"]["status"] = "OPEN \u2014 approved"
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "notice checklist status changed"):
            self.run_dry_run()

    def test_critical_action_change_fails(self) -> None:
        provenance, inventory = self.read_tree()
        items = provenance["rights_review"]["notice_checklist"]["items"]
        target = next(item for item in items if item["id"] == "RIGHTS-04")
        target["action"] = "Reworded action with the same blocking status."
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "action changed"):
            self.run_dry_run()

    def test_critical_evidence_change_fails(self) -> None:
        provenance, inventory = self.read_tree()
        items = provenance["rights_review"]["notice_checklist"]["items"]
        target = next(item for item in items if item["id"] == "RIGHTS-02")
        target["evidence"] = "Reworded evidence with the same blocking status."
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "evidence changed"):
            self.run_dry_run()

    def test_branch_push_authorization_matches_canonical_contract(self) -> None:
        self.assertEqual(TEST_BRANCH_PUSH_AUTHORIZATION, DRY_RUN.EXPECTED_BRANCH_PUSH_AUTHORIZATION)
        result = self.run_dry_run()
        self.assertEqual(result["blocking_open"], BLOCKING_OPEN)
        self.assertEqual(result["members"], EXPECTED_MEMBERS)
        self.assertFalse(result["publication_authorized"])
        record = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(
            record["gate"]["review_ci_branch_push_authorization"],
            TEST_BRANCH_PUSH_AUTHORIZATION,
        )
        self.assertIs(record["publication_authorized"], False)

    def test_branch_push_status_tamper_fails(self) -> None:
        provenance, inventory = self.read_tree()
        auth = provenance["rights_review"]["review_ci_branch_push_authorization"]
        auth["status"] = "AUTHORIZED"
        inventory["rights_gate"]["review_ci_branch_push_authorization"] = copy.deepcopy(auth)
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "push authorization changed"):
            self.run_dry_run()

    def test_branch_push_scope_tamper_fails(self) -> None:
        provenance, inventory = self.read_tree()
        auth = provenance["rights_review"]["review_ci_branch_push_authorization"]
        auth["scope"] = "Push the branch for review, CI, and publication."
        inventory["rights_gate"]["review_ci_branch_push_authorization"] = copy.deepcopy(auth)
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "push authorization changed"):
            self.run_dry_run()

    def test_branch_push_not_authorized_tamper_fails(self) -> None:
        provenance, inventory = self.read_tree()
        auth = provenance["rights_review"]["review_ci_branch_push_authorization"]
        auth["not_authorized"] = [item for item in auth["not_authorized"] if "attestation" not in item]
        inventory["rights_gate"]["review_ci_branch_push_authorization"] = copy.deepcopy(auth)
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "push authorization changed"):
            self.run_dry_run()

    def test_branch_push_rights_gate_unchanged_tamper_fails(self) -> None:
        provenance, inventory = self.read_tree()
        auth = provenance["rights_review"]["review_ci_branch_push_authorization"]
        auth["rights_gate_unchanged"] = "Gate resolved."
        inventory["rights_gate"]["review_ci_branch_push_authorization"] = copy.deepcopy(auth)
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "push authorization changed"):
            self.run_dry_run()

    def test_branch_push_missing_field_fails(self) -> None:
        provenance, inventory = self.read_tree()
        del provenance["rights_review"]["review_ci_branch_push_authorization"]["authorized_on"]
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "push authorization changed|prior field changed"):
            self.run_dry_run()

    def test_branch_push_missing_object_fails(self) -> None:
        provenance, inventory = self.read_tree()
        del inventory["rights_gate"]["review_ci_branch_push_authorization"]
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "review_ci_branch_push_authorization"):
            self.run_dry_run()

    def test_branch_push_mismatch_fails(self) -> None:
        provenance, inventory = self.read_tree()
        inventory["rights_gate"]["review_ci_branch_push_authorization"]["scope"] = "Different scope."
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "push authorization changed|does not match"):
            self.run_dry_run()

    def test_resolved_blocking_item_fails(self) -> None:
        provenance, inventory = self.read_tree()
        for item in provenance["rights_review"]["notice_checklist"]["items"]:
            if item["id"] == "RIGHTS-02":
                item["status"] = "DONE"
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "not OPEN|blocking-open|moved gate"):
            self.run_dry_run()

    def test_notice_resolved_fails(self) -> None:
        provenance, inventory = self.read_tree()
        provenance["rights_review"]["notice_applicability"] = "RESOLVED"
        inventory["rights_gate"]["notice_applicability"] = "RESOLVED"
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "UNRESOLVED"):
            self.run_dry_run()

    def test_forbidden_glob_removal_fails(self) -> None:
        provenance, inventory = self.read_tree()
        inventory["binary_distribution"]["forbidden_globs"] = ["tests/fixtures/**"]
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "forbidden glob"):
            self.run_dry_run()

    def test_fixture_member_rejected(self) -> None:
        provenance, inventory = self.read_tree()
        inventory["binary_distribution"]["archive_members"] = [
            {"source": "target/release/astatine", "archive_path": "astatine", "required": True},
            {"source": "LICENSE-MIT", "archive_path": "LICENSE-MIT", "required": True},
            {
                "source": "tests/fixtures/AstatineMiner.json",
                "archive_path": "fixture.json",
                "required": True,
            },
        ]
        self.write_tree(provenance, inventory)
        with self.assertRaises(DRY_RUN.DryRunError):
            self.run_dry_run()

    def test_fixture_missing_membership_field_fails(self) -> None:
        provenance, inventory = self.read_tree()
        del provenance["fixtures"][0]["release_archive_member"]
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "missing release_archive_member"):
            self.run_dry_run()

    def test_fixture_claiming_membership_fails(self) -> None:
        provenance, inventory = self.read_tree()
        provenance["fixtures"][0]["release_archive_member"] = True
        self.write_tree(provenance, inventory)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "must not be a release archive member"):
            self.run_dry_run()

    def test_traversal_member_rejected(self) -> None:
        provenance, inventory = self.read_tree()
        inventory["binary_distribution"]["archive_members"] = [
            {"source": "target/release/astatine", "archive_path": "astatine", "required": True},
            {"source": "LICENSE-MIT", "archive_path": "LICENSE-MIT", "required": True},
            {"source": "THIRD_PARTY_LICENSES.md", "archive_path": "../evil.md", "required": True},
        ]
        self.write_tree(provenance, inventory)
        with self.assertRaises(DRY_RUN.DryRunError):
            self.run_dry_run()

    def test_symlink_member_rejected(self) -> None:
        outside = Path(self.source_tmp.name) / "outside-target.txt"
        outside.write_text("outside\n", encoding="utf-8")
        link = self.root / "LICENSE-MIT"
        link.unlink()
        os.symlink(outside, link)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "symlink"):
            self.run_dry_run()

    def test_missing_member_rejected(self) -> None:
        (self.root / "target" / "release" / "astatine").unlink()
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "cannot read"):
            self.run_dry_run()

    def test_non_elf_binary_rejected(self) -> None:
        (self.root / "target" / "release" / "astatine").write_bytes(b"not an elf binary\n")
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "ELF"):
            self.run_dry_run()

    def test_wrong_machine_binary_rejected(self) -> None:
        other = bytearray(FAKE_ELF_BINARY)
        other[18:20] = (40).to_bytes(2, "little")
        (self.root / "target" / "release" / "astatine").write_bytes(bytes(other))
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "x86-64"):
            self.run_dry_run()

    def test_toolchain_mismatch_fails(self) -> None:
        with mock.patch.object(DRY_RUN, "observed_toolchain", return_value="rustc 1.95.0 (e408947bf 2026-03-25)"):
            with self.assertRaisesRegex(DRY_RUN.DryRunError, "pinned Rust"):
                self.run_dry_run()

    def test_cargo_mismatch_fails(self) -> None:
        with mock.patch.object(DRY_RUN, "observed_cargo_version", return_value="cargo 1.95.0 (29ea6fb6a 2026-03-24)"):
            with self.assertRaisesRegex(DRY_RUN.DryRunError, "pinned Cargo"):
                self.run_dry_run()

    def test_repository_mismatch_fails(self) -> None:
        (self.root / "support" / "release-repository.txt").write_text("SomeoneElse/other\n", encoding="utf-8")
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "release repository changed"):
            self.run_dry_run()

    def test_release_mode_always_fails(self) -> None:
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "no release path"):
            DRY_RUN.run(source_root=self.root, output_dir=self.out, mode="release")

    def test_output_dir_inside_source_tree_fails(self) -> None:
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "outside the source tree"):
            DRY_RUN.run(
                source_root=self.root,
                output_dir=self.root / "nested-out",
                mode="dry-run",
            )
        self.assertFalse(
            (self.root / "nested-out").exists(),
            "an in-tree output path must not be created before containment is checked",
        )

    def test_output_dir_alias_does_not_create_in_tree_intermediate(self) -> None:
        alias = (
            self.root
            / "missing"
            / ".."
            / ".."
            / Path(self.out_tmp.name).name
            / "out"
        )
        result = self.run_dry_run(output_dir=alias)
        self.assertTrue(Path(result["artifact_path"]).is_file())
        self.assertFalse(
            (self.root / "missing").exists(),
            "an aliased output path must not create in-tree intermediate directories",
        )

    def test_untracked_nonmember_source_fails(self) -> None:
        (self.root / "src").mkdir(exist_ok=True)
        (self.root / "src" / "injected.rs").write_text("fn injected() {}\n", encoding="utf-8")
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "not clean at HEAD"):
            self.run_dry_run()

    def test_nonempty_output_dir_fails(self) -> None:
        self.out.mkdir(parents=True)
        (self.out / "junk.txt").write_text("junk\n", encoding="utf-8")
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "new or empty"):
            self.run_dry_run()

    def test_preexisting_output_file_fails_without_touching_source(self) -> None:
        before = {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in sorted(self.root.rglob("*"))
            if ".git" not in path.parts and path.is_file() and not path.is_symlink()
        }
        self.out.mkdir(parents=True)
        (self.out / "SHA256SUMS").write_bytes(b"stale\n")
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "new or empty|overwrite"):
            self.run_dry_run()
        after = {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in sorted(self.root.rglob("*"))
            if ".git" not in path.parts and path.is_file() and not path.is_symlink()
        }
        self.assertEqual(before, after)

    def test_symlinked_output_file_fails_without_touching_source(self) -> None:
        before = {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in sorted(self.root.rglob("*"))
            if ".git" not in path.parts and path.is_file() and not path.is_symlink()
        }
        self.out.mkdir(parents=True)
        target = self.root / "LICENSE-MIT"
        os.symlink(target, self.out / "release-provenance.json")
        with self.assertRaises(DRY_RUN.DryRunError):
            self.run_dry_run()
        after = {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in sorted(self.root.rglob("*"))
            if ".git" not in path.parts and path.is_file() and not path.is_symlink()
        }
        self.assertEqual(before, after)
        self.assertEqual((self.root / "LICENSE-MIT").read_bytes(), b"test MIT\n")

    def test_symlinked_output_dir_fails(self) -> None:
        real = Path(self.out_tmp.name) / "real-out"
        real.mkdir()
        os.symlink(real, self.out)
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "symlink"):
            self.run_dry_run()

    def test_git_clean_repo_passes_verified(self) -> None:
        result = self.run_dry_run()
        self.assertTrue(result["git_verified"])
        self.assertTrue(result["source_clean_at_head"])
        record = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        self.assertTrue(record["git_verified"])
        self.assertTrue(record["source_clean_at_head"])
        self.assertEqual(record["git_status"].get("LICENSE-MIT"), "clean")
        self.assertEqual(record["git_status"].get("THIRD_PARTY_LICENSES.md"), "clean")
        self.assertEqual(record["git_status"].get("target/release/astatine"), "untracked-build-artifact")
        gate_status = record["source_clean_status"]
        self.assertTrue(gate_status["gate_files_clean"]["tests/fixtures/PROVENANCE.json"])
        self.assertTrue(gate_status["gate_files_clean"]["support/release/distribution-inventory.json"])
        self.assertIn("unverified", record["binary_build_linkage"])
        self.assertNotEqual(record["commit"], "unavailable")

    def test_git_dirty_tracked_member_fails(self) -> None:
        (self.root / "LICENSE-MIT").write_text("tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "not clean at HEAD"):
            self.run_dry_run()

    def test_git_dirty_nonmember_source_fails(self) -> None:
        (self.root / ".gitignore").write_text("target/\nignored-extra/\n", encoding="utf-8")
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "not clean at HEAD"):
            self.run_dry_run()

    def test_git_ignored_nontarget_file_not_inspected(self) -> None:
        with open(self.root / ".gitignore", "a", encoding="utf-8") as handle:
            handle.write("ignored.txt\n")
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-q", "-m", "ignore extra"], check=True)
        (self.root / "ignored.txt").write_text("not inspected\n", encoding="utf-8")
        result = self.run_dry_run()
        self.assertTrue(result["source_clean_at_head"])

    def test_git_untracked_nonignored_file_fails(self) -> None:
        (self.root / "surprise.txt").write_text("untracked\n", encoding="utf-8")
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "not clean at HEAD"):
            self.run_dry_run()

    def test_git_dirty_gate_file_fails(self) -> None:
        provenance, inventory = self.read_tree()
        (self.root / "support" / "release" / "distribution-inventory.json").write_text(
            json.dumps(inventory, indent=4, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "not clean at HEAD"):
            self.run_dry_run()

    def test_git_untracked_document_fails(self) -> None:
        subprocess.run(
            ["git", "-C", str(self.root), "rm", "-q", "--cached", "LICENSE-MIT"], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-q", "-m", "untrack license"], check=True
        )
        (self.root / "LICENSE-MIT").write_text("replaced while untracked\n", encoding="utf-8")
        with self.assertRaisesRegex(
            DRY_RUN.DryRunError, "not clean at HEAD|not tracked by git"
        ):
            self.run_dry_run()

    def test_provenance_record_is_truthful(self) -> None:
        result = self.run_dry_run()
        self.assertTrue(result["git_verified"])
        self.assertTrue(result["source_clean_at_head"])
        record = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        self.assertIs(record["publication_authorized"], False)
        self.assertEqual(record["mode"], "dry-run")
        self.assertEqual(record["target"], "x86_64-unknown-linux-gnu")
        self.assertEqual(record["distribution_target"], "x86_64-unknown-linux-gnu")
        self.assertEqual(record["package_name"], "astatine-cli-rust")
        self.assertEqual(record["package_version"], "0.1.0-testnet.0")
        self.assertEqual(record["binary_name"], "astatine")
        self.assertEqual(record["build_profile"], "release")
        self.assertEqual(record["cargo_command"], "cargo build --locked --release")
        self.assertEqual(record["cargo_lock_sha256"], hashlib.sha256(TEST_LOCK_BYTES).hexdigest())
        self.assertEqual(
            record["cargo_lock_sha256"],
            hashlib.sha256((self.root / "Cargo.lock").read_bytes()).hexdigest(),
        )
        self.assertEqual(record["observed_cargo_version"], LEGIT_CARGO_LINE)
        self.assertEqual(record["binary_install"]["archive_path"], "astatine")
        self.assertEqual(record["binary_install"]["source"], "target/release/astatine")
        self.assertEqual(record["binary_install"]["placement"], "archive root")
        self.assertIn("unverified", record["binary_build_linkage"])
        self.assertEqual(record["pinned_toolchain"], "1.94.1")
        self.assertEqual(record["observed_toolchain"], LEGIT_RUSTC_LINE)
        self.assertIs(record["git_verified"], True)
        self.assertIs(record["source_clean_at_head"], True)
        self.assertTrue(record["source_clean_status"]["gate_files_clean"]["tests/fixtures/PROVENANCE.json"])
        self.assertTrue(record["source_clean_status"]["gate_files_clean"]["support/release/distribution-inventory.json"])
        self.assertNotIn("source_root", record)
        self.assertNotIn("invocation", record)
        self.assertEqual(record["provenance_path"], "tests/fixtures/PROVENANCE.json")
        self.assertEqual(record["inventory_path"], "support/release/distribution-inventory.json")
        self.assertNotIn(str(self.root.resolve()), json.dumps(record))
        self.assertIn("no absolute checkout path", record["notes"])
        self.assertIn("no raw invocation", record["notes"])
        self.assertEqual(record["artifact"]["sha256"], result["artifact_sha256"])
        self.assertEqual(
            record["artifact"]["sha256"],
            hashlib.sha256(Path(result["artifact_path"]).read_bytes()).hexdigest(),
        )
        by_path = {m["archive_path"]: m for m in record["artifact"]["members"]}
        self.assertEqual(
            {m["archive_path"]: m["sha256"] for m in record["artifact"]["members"]},
            result["member_hashes"],
        )
        for archive_path, entry in by_path.items():
            if entry.get("generated"):
                self.assertEqual(entry["source"], f"generated:{archive_path}")
                self.assertEqual(entry["mode"], "0o644")
            else:
                data = DRY_RUN.read_confined_bytes(self.root.resolve(), entry["source"], "check")
                self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])
        self.assertEqual(record["gate"]["publication_decision"], PUBLICATION_DECISION)
        self.assertEqual(record["gate"]["blocking_open"], BLOCKING_OPEN)
        self.assertEqual(record["gate"]["binary_status"], "BLOCKED")
        self.assertEqual(record["gate"]["source_status"], "BLOCKED")
        self.assertEqual(record["gate"]["all_archive_members"], EXPECTED_MEMBERS)
        checksums = (self.out / "SHA256SUMS").read_text(encoding="utf-8")
        self.assertIn(result["artifact_sha256"], checksums)
        self.assertIn("astatine-x86_64-unknown-linux-gnu.dry-run.tar.gz", checksums)

    def test_provenance_sanitizes_toolchain_env(self) -> None:
        self.assertEqual(DRY_RUN.sanitize_toolchain_env("1.94.1"), "1.94.1")
        self.assertEqual(DRY_RUN.sanitize_toolchain_env("not-set"), "not-set")
        self.assertEqual(DRY_RUN.sanitize_toolchain_env(None), "not-set")
        self.assertEqual(
            DRY_RUN.sanitize_toolchain_env("/home/user/.rustup/toolchains/1.94.1"),
            "redacted-unexpected-value",
        )
        self.assertEqual(DRY_RUN.sanitize_toolchain_env(""), "redacted-unexpected-value")
        with mock.patch.dict(os.environ, {"RUSTUP_TOOLCHAIN": "/tmp/custom-toolchain"}):
            result = self.run_dry_run()
            record = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
            self.assertEqual(record["rustup_toolchain_env"], "redacted-unexpected-value")
            self.assertNotIn("/tmp/custom-toolchain", json.dumps(record))
        with mock.patch.dict(os.environ, {"RUSTUP_TOOLCHAIN": "1.94.1"}):
            second_out = Path(self.out_tmp.name) / "out-env-pin"
            DRY_RUN.run(source_root=self.root, output_dir=second_out, mode="dry-run")
            record = json.loads((second_out / "release-provenance.json").read_text(encoding="utf-8"))
            self.assertEqual(record["rustup_toolchain_env"], "1.94.1")

    def test_provenance_record_contains_no_absolute_paths(self) -> None:
        result = self.run_dry_run()
        record = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        dumped = json.dumps(record)
        self.assertNotIn(str(self.root.resolve()), dumped)
        self.assertNotIn(str(self.out.resolve()), dumped)
        self.assertNotIn(str(Path(self.out_tmp.name).resolve()), dumped)
        for value in (record.get("rustup_toolchain_env", ""),):
            self.assertNotIn("/", value)

    def test_main_stdout_withholds_absolute_paths(self) -> None:
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = DRY_RUN.main(["--mode", "dry-run", "--output-dir", str(self.out), "--source-root", str(self.root)])
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["status"], "PASS")
        self.assertNotIn("artifact_path", payload)
        self.assertNotIn("provenance_path", payload)
        self.assertEqual(payload["artifact_filename"], "astatine-x86_64-unknown-linux-gnu.dry-run.tar.gz")
        dumped = buf.getvalue()
        self.assertNotIn(str(self.root.resolve()), dumped)
        self.assertNotIn(str(self.out.resolve()), dumped)

    def test_error_messages_withhold_absolute_paths(self) -> None:
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "outside the source tree"):
            DRY_RUN.run(
                source_root=self.root,
                output_dir=self.root / "nested-out",
                mode="dry-run",
            )
        try:
            DRY_RUN.run(
                source_root=self.root,
                output_dir=self.root / "nested-out",
                mode="dry-run",
            )
        except DRY_RUN.DryRunError as error:
            self.assertNotIn(str(self.root.resolve()), str(error))
        else:
            self.fail("expected DryRunError")

    def test_git_command_timeout_fails_closed_without_path_leak(self) -> None:
        import subprocess as _subprocess

        with mock.patch(
            "subprocess.run",
            side_effect=_subprocess.TimeoutExpired(
                cmd=["git", "-C", str(self.root.resolve()), "rev-parse", "HEAD"],
                timeout=30,
            ),
        ):
            with self.assertRaises(DRY_RUN.DryRunError):
                DRY_RUN.run(
                    source_root=self.root,
                    output_dir=self.out,
                    mode="dry-run",
                )
        try:
            with mock.patch(
                "subprocess.run",
                side_effect=_subprocess.TimeoutExpired(
                    cmd=["git", "-C", str(self.root.resolve()), "status"],
                    timeout=30,
                ),
            ):
                DRY_RUN.run(
                    source_root=self.root,
                    output_dir=self.out,
                    mode="dry-run",
                )
        except DRY_RUN.DryRunError as error:
            self.assertNotIn(str(self.root.resolve()), str(error))
            self.assertNotIn("rev-parse", str(error))
        else:
            self.fail("expected DryRunError")

    def test_verify_source_clean_os_error_sanitized(self) -> None:
        with mock.patch.object(
            DRY_RUN,
            "git_command",
            side_effect=OSError(2, "No such file or directory: '/tmp/astatine-secret-checkout'"),
        ):
            with self.assertRaisesRegex(DRY_RUN.DryRunError, "cannot verify source cleanliness"):
                DRY_RUN.verify_source_clean(self.root.resolve())
        try:
            with mock.patch.object(
                DRY_RUN,
                "git_command",
                side_effect=OSError(2, "No such file or directory: '/tmp/astatine-secret-checkout'"),
            ):
                DRY_RUN.verify_source_clean(self.root.resolve())
        except DRY_RUN.DryRunError as error:
            self.assertNotIn("/tmp/astatine-secret-checkout", str(error))
            self.assertNotIn("No such file", str(error))
        else:
            self.fail("expected DryRunError")

    def test_gate_file_timeout_fails_closed_without_path_leak(self) -> None:
        import subprocess as _subprocess

        real_root = str(self.root.resolve())
        calls = {"n": 0}

        def _gate_timeout(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] <= 3:
                return _subprocess.CompletedProcess(args=list(args), returncode=0, stdout="")
            raise _subprocess.TimeoutExpired(
                cmd=["git", "-C", real_root, "diff", "--quiet", "HEAD"],
                timeout=30,
            )

        with mock.patch.object(DRY_RUN, "git_command", side_effect=_gate_timeout):
            with self.assertRaisesRegex(DRY_RUN.DryRunError, "cannot verify gate-file cleanliness"):
                DRY_RUN.verify_source_clean(self.root.resolve())
        try:
            calls["n"] = 0
            with mock.patch.object(DRY_RUN, "git_command", side_effect=_gate_timeout):
                DRY_RUN.verify_source_clean(self.root.resolve())
        except DRY_RUN.DryRunError as error:
            self.assertNotIn(real_root, str(error))
        else:
            self.fail("expected DryRunError")

    def test_source_root_resolve_runtime_error_sanitized(self) -> None:
        with mock.patch.object(
            Path,
            "resolve",
            side_effect=RuntimeError("Symlink loop '/tmp/astatine-secret-checkout'"),
        ):
            with self.assertRaises(DRY_RUN.DryRunError):
                DRY_RUN.run(
                    source_root=self.root,
                    output_dir=self.out,
                    mode="dry-run",
                )
        try:
            with mock.patch.object(
                Path,
                "resolve",
                side_effect=RuntimeError("Symlink loop '/tmp/astatine-secret-checkout'"),
            ):
                DRY_RUN.run(
                    source_root=self.root,
                    output_dir=self.out,
                    mode="dry-run",
                )
        except DRY_RUN.DryRunError as error:
            self.assertNotIn("/tmp/astatine-secret-checkout", str(error))
            self.assertNotIn("Symlink loop", str(error))
        else:
            self.fail("expected DryRunError")

    def test_member_status_timeout_requires_git_verified(self) -> None:
        with mock.patch.object(DRY_RUN, "git_member_status", return_value=None):
            with self.assertRaisesRegex(
                DRY_RUN.DryRunError, "not verifiably clean at HEAD"
            ):
                DRY_RUN.run(
                    source_root=self.root,
                    output_dir=self.out,
                    mode="dry-run",
                )
        try:
            with mock.patch.object(DRY_RUN, "git_member_status", return_value=None):
                DRY_RUN.run(
                    source_root=self.root,
                    output_dir=self.out,
                    mode="dry-run",
                )
        except DRY_RUN.DryRunError as error:
            self.assertNotIn(str(self.root.resolve()), str(error))
        else:
            self.fail("expected DryRunError")

    def test_provenance_records_required_hosted_ci_not_verified(self) -> None:
        result = self.run_dry_run()
        self.assertTrue(result["source_clean_at_head"])
        record = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        required_ci = record.get("required_hosted_ci")
        self.assertIsInstance(required_ci, dict)
        self.assertEqual(required_ci.get("status"), "required-not-verified")
        self.assertIs(required_ci.get("verified_by_this_script"), False)
        self.assertIn("green Rust CI", required_ci.get("requirement", ""))
        self.assertIn("exact", required_ci.get("requirement", ""))

    def test_nongit_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="astatine-dryrun-plain-") as plain:
            root = Path(plain)
            (root / "tests" / "fixtures").mkdir(parents=True)
            (root / "support" / "release").mkdir(parents=True)
            (root / "target" / "release").mkdir(parents=True)
            (root / "tests" / "fixtures" / "PROVENANCE.json").write_text(
                json.dumps(make_provenance(), indent=2) + "\n", encoding="utf-8"
            )
            (root / "support" / "release" / "distribution-inventory.json").write_text(
                json.dumps(make_inventory(), indent=2) + "\n", encoding="utf-8"
            )
            (root / "target" / "release" / "astatine").write_bytes(FAKE_ELF_BINARY)
            (root / "LICENSE-MIT").write_text("test MIT\n", encoding="utf-8")
            (root / "THIRD_PARTY_LICENSES.md").write_text("test notices\n", encoding="utf-8")
            (root / "Cargo.toml").write_text(TEST_CARGO_TOML, encoding="utf-8")
            (root / "Cargo.lock").write_bytes(TEST_LOCK_BYTES)
            (root / "support" / "release-repository.txt").write_text(TEST_REPOSITORY, encoding="utf-8")
            out = Path(self.out_tmp.name) / "plain-out"
            with self.assertRaisesRegex(DRY_RUN.DryRunError, "verifiably clean Git checkout"):
                DRY_RUN.run(source_root=root, output_dir=out, mode="dry-run")


class DryRunToolchainStrictnessTests(unittest.TestCase):
    """Strict complete-line toolchain validation (R-01).

    The builder must accept only the complete official single-line
    Rust/Cargo 1.94.1 outputs, with at most one optional trailing LF or CRLF.
    A synthetic toolchain emitting the correct prefix plus an extra marker
    line or same-line suffix must fail closed, and rejected content must never
    reach provenance/BUILD-INFO or error text.
    """

    def setUp(self) -> None:
        self.source_tmp = tempfile.TemporaryDirectory(prefix="astatine-dryrun-strict-src-")
        self.out_tmp = tempfile.TemporaryDirectory(prefix="astatine-dryrun-strict-out-")
        self.root = Path(self.source_tmp.name)
        self.out = Path(self.out_tmp.name) / "out"
        self.toolchain_patch = mock.patch.object(
            DRY_RUN, "observed_toolchain", return_value=LEGIT_RUSTC_LINE
        )
        self.toolchain_patch.start()
        self.cargo_patch = mock.patch.object(
            DRY_RUN, "observed_cargo_version", return_value=LEGIT_CARGO_LINE
        )
        self.cargo_patch.start()
        self.write_tree(make_provenance(), make_inventory())
        (self.root / ".gitignore").write_text("target/\n", encoding="utf-8")
        init_git_repo(self.root)

    def tearDown(self) -> None:
        self.cargo_patch.stop()
        self.toolchain_patch.stop()
        self.source_tmp.cleanup()
        self.out_tmp.cleanup()

    def write_tree(self, provenance: dict, inventory: dict) -> None:
        (self.root / "tests" / "fixtures").mkdir(parents=True, exist_ok=True)
        (self.root / "support" / "release").mkdir(parents=True, exist_ok=True)
        (self.root / "target" / "release").mkdir(parents=True, exist_ok=True)
        (self.root / "tests" / "fixtures" / "PROVENANCE.json").write_text(
            json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
        )
        (self.root / "support" / "release" / "distribution-inventory.json").write_text(
            json.dumps(inventory, indent=2) + "\n", encoding="utf-8"
        )
        (self.root / "target" / "release" / "astatine").write_bytes(FAKE_ELF_BINARY)
        (self.root / "LICENSE-MIT").write_text("test MIT\n", encoding="utf-8")
        (self.root / "THIRD_PARTY_LICENSES.md").write_text("test notices\n", encoding="utf-8")
        (self.root / "Cargo.toml").write_text(TEST_CARGO_TOML, encoding="utf-8")
        (self.root / "Cargo.lock").write_bytes(TEST_LOCK_BYTES)
        (self.root / "support" / "release-repository.txt").write_text(TEST_REPOSITORY, encoding="utf-8")

    def run_dry_run(self, **overrides):
        kwargs = {"source_root": self.root, "output_dir": self.out, "mode": "dry-run"}
        kwargs.update(overrides)
        return DRY_RUN.run(**kwargs)

    def assert_run_rejects_and_writes_nothing(self, rustc_value: str, cargo_value: str, marker: str = "MARKER") -> None:
        with mock.patch.object(DRY_RUN, "observed_toolchain", return_value=rustc_value):
            with mock.patch.object(DRY_RUN, "observed_cargo_version", return_value=cargo_value):
                try:
                    DRY_RUN.run(source_root=self.root, output_dir=self.out, mode="dry-run")
                except DRY_RUN.DryRunError as error:
                    message = str(error)
                    self.assertNotIn(marker, message)
                    self.assertNotIn("\n", message)
                    self.assertNotIn("\r", message)
                    self.assertNotIn("\x00", message)
                    self.assertNotIn("\x1b", message)
                else:
                    self.fail("expected DryRunError for malicious toolchain output")
        self.assertFalse(self.out.exists(), "malicious toolchain output must not create any output")

    def test_valid_canonical_lines_pass(self) -> None:
        result = self.run_dry_run()
        record = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(record["observed_toolchain"], LEGIT_RUSTC_LINE)
        self.assertEqual(record["observed_cargo_version"], LEGIT_CARGO_LINE)
        with tarfile.open(result["artifact_path"], mode="r") as tar:
            build_info = json.loads(tar.extractfile("BUILD-INFO.json").read().decode("utf-8"))
        self.assertEqual(build_info["build"]["rustc_version"], LEGIT_RUSTC_LINE)
        self.assertEqual(build_info["build"]["cargo_version"], LEGIT_CARGO_LINE)

    def test_normalize_accepts_optional_trailing_lf_and_crlf(self) -> None:
        self.assertEqual(
            DRY_RUN._normalize_rustc_output((LEGIT_RUSTC_LINE + "\n").encode("utf-8")),
            LEGIT_RUSTC_LINE,
        )
        self.assertEqual(
            DRY_RUN._normalize_rustc_output((LEGIT_RUSTC_LINE + "\r\n").encode("utf-8")),
            LEGIT_RUSTC_LINE,
        )
        self.assertEqual(
            DRY_RUN._normalize_cargo_output((LEGIT_CARGO_LINE + "\n").encode("utf-8")),
            LEGIT_CARGO_LINE,
        )
        self.assertEqual(
            DRY_RUN._normalize_cargo_output((LEGIT_CARGO_LINE + "\r\n").encode("utf-8")),
            LEGIT_CARGO_LINE,
        )
        self.assertEqual(DRY_RUN._normalize_rustc_output(LEGIT_RUSTC_LINE.encode("utf-8")), LEGIT_RUSTC_LINE)
        self.assertEqual(DRY_RUN._normalize_cargo_output(LEGIT_CARGO_LINE.encode("utf-8")), LEGIT_CARGO_LINE)

    def test_observed_helpers_accept_trailing_newline_via_subprocess(self) -> None:
        # End-to-end through the real bounded helper: producers emit the
        # official line with a single trailing LF / CRLF.
        rustc_script = "import sys; sys.stdout.buffer.write(%r)" % (
            (LEGIT_RUSTC_LINE + "\n").encode("utf-8"),
        )
        cargo_script = "import sys; sys.stdout.buffer.write(%r)" % (
            (LEGIT_CARGO_LINE + "\r\n").encode("utf-8"),
        )
        raw_rustc = DRY_RUN._capture_version_bytes([sys.executable, "-c", rustc_script], timeout=5)
        raw_cargo = DRY_RUN._capture_version_bytes([sys.executable, "-c", cargo_script], timeout=5)
        self.assertEqual(raw_rustc, (LEGIT_RUSTC_LINE + "\n").encode("utf-8"))
        self.assertEqual(raw_cargo, (LEGIT_CARGO_LINE + "\r\n").encode("utf-8"))
        self.assertEqual(DRY_RUN._normalize_rustc_output(raw_rustc), LEGIT_RUSTC_LINE)
        self.assertEqual(DRY_RUN._normalize_cargo_output(raw_cargo), LEGIT_CARGO_LINE)
        # Wiring: observed_* normalizes trailing newlines via the new helper.
        self.toolchain_patch.stop()
        self.cargo_patch.stop()
        try:
            with mock.patch.object(
                DRY_RUN, "_capture_version_bytes", return_value=(LEGIT_RUSTC_LINE + "\n").encode("utf-8")
            ) as rustc_cap:
                self.assertEqual(DRY_RUN.observed_toolchain(), LEGIT_RUSTC_LINE)
                rustc_cap.assert_called_once()
            with mock.patch.object(
                DRY_RUN, "_capture_version_bytes", return_value=(LEGIT_CARGO_LINE + "\r\n").encode("utf-8")
            ) as cargo_cap:
                self.assertEqual(DRY_RUN.observed_cargo_version(), LEGIT_CARGO_LINE)
                cargo_cap.assert_called_once()
        finally:
            self.toolchain_patch.start()
            self.cargo_patch.start()

    def test_prefix_plus_extra_line_marker_rejected(self) -> None:
        evil_rustc = LEGIT_RUSTC_LINE + "\nMARKER"
        evil_cargo = LEGIT_CARGO_LINE + "\nMARKER"
        self.assertIsNone(DRY_RUN._normalize_rustc_output(evil_rustc.encode("utf-8")))
        self.assertIsNone(DRY_RUN._normalize_cargo_output(evil_cargo.encode("utf-8")))
        self.assert_run_rejects_and_writes_nothing(evil_rustc, LEGIT_CARGO_LINE)
        self.assert_run_rejects_and_writes_nothing(LEGIT_RUSTC_LINE, evil_cargo)

    def test_same_line_suffix_marker_rejected(self) -> None:
        evil_rustc = LEGIT_RUSTC_LINE + " MARKER"
        evil_cargo = LEGIT_CARGO_LINE + " MARKER"
        self.assertIsNone(DRY_RUN._normalize_rustc_output(evil_rustc.encode("utf-8")))
        self.assertIsNone(DRY_RUN._normalize_cargo_output(evil_cargo.encode("utf-8")))
        self.assert_run_rejects_and_writes_nothing(evil_rustc, LEGIT_CARGO_LINE)
        self.assert_run_rejects_and_writes_nothing(LEGIT_RUSTC_LINE, evil_cargo)

    def test_embedded_controls_rejected(self) -> None:
        rustc_cases = [
            LEGIT_RUSTC_LINE + "\r",
            LEGIT_RUSTC_LINE + "\r\n\n",
            LEGIT_RUSTC_LINE + "\n\n",
            LEGIT_RUSTC_LINE + "\x00",
            LEGIT_RUSTC_LINE + "\x1b[31m",
            LEGIT_RUSTC_LINE + "\nsecond-line",
        ]
        cargo_cases = [
            LEGIT_CARGO_LINE + "\r",
            LEGIT_CARGO_LINE + "\r\n\n",
            LEGIT_CARGO_LINE + "\n\n",
            LEGIT_CARGO_LINE + "\x00",
            LEGIT_CARGO_LINE + "\x1b[0m",
            LEGIT_CARGO_LINE + "\nsecond-line",
        ]
        for rustc_value in rustc_cases:
            with self.subTest(tool="rustc", value=repr(rustc_value)):
                self.assertIsNone(DRY_RUN._normalize_rustc_output(rustc_value.encode("utf-8")))
                self.assert_run_rejects_and_writes_nothing(rustc_value, LEGIT_CARGO_LINE, marker="MARKER")
        for cargo_value in cargo_cases:
            with self.subTest(tool="cargo", value=repr(cargo_value)):
                self.assertIsNone(DRY_RUN._normalize_cargo_output(cargo_value.encode("utf-8")))
                self.assert_run_rejects_and_writes_nothing(LEGIT_RUSTC_LINE, cargo_value, marker="MARKER")

    def test_nul_and_ansi_bytes_rejected(self) -> None:
        self.assertIsNone(DRY_RUN._normalize_rustc_output(LEGIT_RUSTC_LINE.encode("utf-8") + b"\x00"))
        self.assertIsNone(DRY_RUN._normalize_cargo_output(LEGIT_CARGO_LINE.encode("utf-8") + b"\x1b[0m"))
        self.assert_run_rejects_and_writes_nothing(LEGIT_RUSTC_LINE + "\x00", LEGIT_CARGO_LINE)
        self.assert_run_rejects_and_writes_nothing(LEGIT_RUSTC_LINE, LEGIT_CARGO_LINE + "\x1b[0m")

    def test_oversized_output_rejected(self) -> None:
        oversized_rustc = LEGIT_RUSTC_LINE + " " + "x" * 600
        oversized_cargo = LEGIT_CARGO_LINE + " " + "y" * 600
        self.assertGreater(len(oversized_rustc.encode("utf-8")), DRY_RUN.MAX_TOOLCHAIN_OUTPUT_BYTES)
        self.assertGreater(len(oversized_cargo.encode("utf-8")), DRY_RUN.MAX_TOOLCHAIN_OUTPUT_BYTES)
        self.assertIsNone(DRY_RUN._normalize_rustc_output(oversized_rustc.encode("utf-8")))
        self.assertIsNone(DRY_RUN._normalize_cargo_output(oversized_cargo.encode("utf-8")))
        # True bounded capture: a producer emitting 10000 bytes must be killed
        # after MAX+1 bytes without buffering the whole flood.
        flood_script = "import sys; sys.stdout.buffer.write(b'x' * 10000)"
        start = time.monotonic()
        raw = DRY_RUN._capture_version_bytes([sys.executable, "-c", flood_script], timeout=5)
        elapsed = time.monotonic() - start
        self.assertIsNone(raw)
        self.assertLess(elapsed, 5)
        self.toolchain_patch.stop()
        try:
            with mock.patch.object(DRY_RUN, "_capture_version_bytes", return_value=None):
                self.assertEqual(DRY_RUN.observed_toolchain(), "not-observed")
        finally:
            self.toolchain_patch.start()
        self.assert_run_rejects_and_writes_nothing(oversized_rustc, LEGIT_CARGO_LINE)
        self.assert_run_rejects_and_writes_nothing(LEGIT_RUSTC_LINE, oversized_cargo)

    def test_bounded_capture_rejects_oversized_stdout_without_unbounded_buffer(self) -> None:
        flood_script = "import sys; sys.stdout.buffer.write(b'A' * 100000)"
        start = time.monotonic()
        raw = DRY_RUN._capture_version_bytes([sys.executable, "-c", flood_script], timeout=5)
        elapsed = time.monotonic() - start
        self.assertIsNone(raw)
        self.assertLess(elapsed, 5)

    def test_bounded_capture_ignores_stderr_flood(self) -> None:
        # Stderr is DEVNULL: a multi-megabyte stderr flood must not block or
        # affect the valid stdout line.
        script = (
            "import sys; "
            "sys.stderr.buffer.write(b'e' * 2000000); "
            "sys.stdout.buffer.write(%r)" % ((LEGIT_RUSTC_LINE + "\n").encode("utf-8"),)
        )
        start = time.monotonic()
        raw = DRY_RUN._capture_version_bytes([sys.executable, "-c", script], timeout=5)
        elapsed = time.monotonic() - start
        self.assertEqual(raw, (LEGIT_RUSTC_LINE + "\n").encode("utf-8"))
        self.assertEqual(DRY_RUN._normalize_rustc_output(raw), LEGIT_RUSTC_LINE)
        self.assertLess(elapsed, 5)

    def test_bounded_capture_nonzero_exit_rejected(self) -> None:
        script = "import sys; sys.stdout.buffer.write(%r); sys.exit(1)" % (
            (LEGIT_RUSTC_LINE + "\n").encode("utf-8"),
        )
        raw = DRY_RUN._capture_version_bytes([sys.executable, "-c", script], timeout=5)
        self.assertIsNone(raw)

    def test_bounded_capture_empty_output_rejected(self) -> None:
        script = "import sys; sys.exit(0)"
        raw = DRY_RUN._capture_version_bytes([sys.executable, "-c", script], timeout=5)
        self.assertIsNone(raw)
        self.assertIsNone(DRY_RUN._capture_version_bytes(["definitely-not-a-real-toolchain-binary-xyz"], timeout=2))

    def test_bounded_capture_hung_process_times_out_fast(self) -> None:
        hung_script = "import time; time.sleep(10)"
        start = time.monotonic()
        raw = DRY_RUN._capture_version_bytes([sys.executable, "-c", hung_script], timeout=0.3)
        elapsed = time.monotonic() - start
        self.assertIsNone(raw)
        self.assertLess(elapsed, 5)
        # Silent process holding the pipe open with no bytes also fails closed.
        silent_script = "import time; time.sleep(10)"
        start = time.monotonic()
        raw_silent = DRY_RUN._capture_version_bytes([sys.executable, "-c", silent_script], timeout=0.3)
        elapsed = time.monotonic() - start
        self.assertIsNone(raw_silent)
        self.assertLess(elapsed, 5)

    def test_bounded_capture_rejects_nonfinite_timeout_before_spawn(self) -> None:
        self.toolchain_patch.stop()
        self.cargo_patch.stop()
        try:
            for value in (float("inf"), float("-inf"), float("nan")):
                with self.subTest(value=value):
                    with mock.patch.object(
                        DRY_RUN.subprocess,
                        "Popen",
                        side_effect=AssertionError(
                            "non-finite timeout must not spawn"
                        ),
                    ):
                        self.assertIsNone(
                            DRY_RUN._capture_version_bytes(
                                ["rustc", "--version"], timeout=value
                            )
                        )
                        self.assertEqual(
                            DRY_RUN.observed_toolchain(timeout=value),
                            "not-observed",
                        )
                        self.assertEqual(
                            DRY_RUN.observed_cargo_version(timeout=value),
                            "not-observed",
                        )
        finally:
            self.toolchain_patch.start()
            self.cargo_patch.start()

    def test_wrong_version_rejected(self) -> None:
        self.assert_run_rejects_and_writes_nothing("rustc 1.95.0 (e408947bf 2026-03-25)", LEGIT_CARGO_LINE)
        self.assert_run_rejects_and_writes_nothing(LEGIT_RUSTC_LINE, "cargo 1.95.0 (29ea6fb6a 2026-03-24)")

    def test_missing_hash_date_rejected(self) -> None:
        self.assert_run_rejects_and_writes_nothing("rustc 1.94.1", LEGIT_CARGO_LINE)
        self.assert_run_rejects_and_writes_nothing(LEGIT_RUSTC_LINE, "cargo 1.94.1")
        self.assert_run_rejects_and_writes_nothing("rustc 1.94.1 (test)", LEGIT_CARGO_LINE)
        self.assert_run_rejects_and_writes_nothing(LEGIT_RUSTC_LINE, "cargo 1.94.1 (test)")
        self.assertIsNone(DRY_RUN._normalize_rustc_output(b"rustc 1.94.1"))
        self.assertIsNone(DRY_RUN._normalize_cargo_output(b"cargo 1.94.1 (test)"))

    def test_not_observed_rejected(self) -> None:
        with mock.patch.object(DRY_RUN, "observed_toolchain", return_value="not-observed"):
            with self.assertRaisesRegex(DRY_RUN.DryRunError, "pinned Rust"):
                DRY_RUN.run(source_root=self.root, output_dir=self.out, mode="dry-run")
        self.assertFalse(self.out.exists())
        with mock.patch.object(DRY_RUN, "observed_cargo_version", return_value="not-observed"):
            with self.assertRaisesRegex(DRY_RUN.DryRunError, "pinned Cargo"):
                DRY_RUN.run(source_root=self.root, output_dir=self.out, mode="dry-run")
        self.assertFalse(self.out.exists())
        # Real bounded helper: nonzero exit and hung process fail closed.
        bad_script = "import sys; sys.exit(1)"
        raw = DRY_RUN._capture_version_bytes([sys.executable, "-c", bad_script], timeout=5)
        self.assertIsNone(raw)
        hung_script = "import time; time.sleep(10)"
        start = time.monotonic()
        raw_hung = DRY_RUN._capture_version_bytes([sys.executable, "-c", hung_script], timeout=0.3)
        elapsed = time.monotonic() - start
        self.assertIsNone(raw_hung)
        self.assertLess(elapsed, 5)
        self.toolchain_patch.stop()
        self.cargo_patch.stop()
        try:
            with mock.patch.object(DRY_RUN, "_capture_version_bytes", return_value=None):
                self.assertEqual(DRY_RUN.observed_toolchain(), "not-observed")
                self.assertEqual(DRY_RUN.observed_cargo_version(), "not-observed")
        finally:
            self.toolchain_patch.start()
            self.cargo_patch.start()

    def test_error_message_withholds_malicious_content(self) -> None:
        evil = LEGIT_RUSTC_LINE + "\nEVIL-MARKER-\x1b[31m-\x00-tail"
        with mock.patch.object(DRY_RUN, "observed_toolchain", return_value=evil):
            try:
                DRY_RUN.run(source_root=self.root, output_dir=self.out, mode="dry-run")
            except DRY_RUN.DryRunError as error:
                message = str(error)
                self.assertNotIn("EVIL-MARKER", message)
                self.assertNotIn("\n", message)
                self.assertNotIn("\r", message)
                self.assertNotIn("\x00", message)
                self.assertNotIn("\x1b", message)
            else:
                self.fail("expected DryRunError")
        self.assertFalse(self.out.exists())

    def test_workflow_uses_complete_line_validation(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertNotIn('.startswith("rustc 1.94.1 ")', text)
        self.assertNotIn(".startswith('rustc 1.94.1 ')", text)
        self.assertNotIn('.startswith("cargo 1.94.1 ")', text)
        self.assertNotIn(".startswith('cargo 1.94.1 ')", text)
        self.assertIn("re.fullmatch", text)
        self.assertIn(r"rustc 1\.94\.1 \(e408947bf 2026-03-25\)", text)
        self.assertIn(r"cargo 1\.94\.1 \(29ea6fb6a 2026-03-24\)", text)


class DryRunWorkflowInvariantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.lines = self.text.splitlines()

    def test_dispatch_only(self) -> None:
        on_block = "\n".join(
            line for line in self.lines if "workflow_dispatch" in line or line.strip().startswith("on:")
        )
        self.assertIn("workflow_dispatch", self.text)
        self.assertIsNone(re.search(r"(?m)^\s*push\s*:", self.text))
        self.assertIsNone(re.search(r"(?m)^\s*pull_request\s*:", self.text))
        self.assertIn("workflow_dispatch", on_block)

    def test_minimal_permissions(self) -> None:
        self.assertIsNotNone(
            re.search(r"(?m)^permissions:\s*\n\s*contents:\s*read\s*$", self.text)
        )
        job_block = self.text[self.text.index("linux-release-dry-run:") :]
        self.assertIn("contents: read", job_block)
        self.assertNotIn("id-token: write", self.text)
        self.assertNotIn("attestations: write", self.text)
        self.assertIsNone(re.search(r"(?m)^\s*id-token\s*:", self.text))
        self.assertIsNone(re.search(r"(?m)^\s*attestations\s*:", self.text))
        self.assertIsNone(re.search(r"(?i)\bsecrets\b", self.text))

    def test_pinned_actions_and_no_publish_paths(self) -> None:
        self.assertIn(f"actions/checkout@{CHECKOUT_SHA}", self.text)
        for line in self.lines:
            match = re.match(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", line)
            if match is None:
                continue
            reference = match.group(1)
            if reference.startswith("./"):
                continue
            digest = reference.rsplit("@", 1)[1]
            self.assertTrue(
                re.fullmatch(r"[0-9a-f]{40}", digest) is not None,
                f"unpinned action: {reference}",
            )
        lowered = self.text.lower()
        self.assertNotIn("upload-artifact", lowered)
        self.assertNotIn("actions/upload", lowered)
        self.assertNotIn("cargo publish", lowered)
        self.assertNotIn("gh release", lowered)
        self.assertIsNone(re.search(r"(?i)\bgh\s+release\b", self.text))
        self.assertNotIn("attest-build-provenance", self.text)
        self.assertNotIn("gh attestation verify", self.text)
        self.assertNotIn("attestations: write", self.text)
        self.assertNotIn("id-token: write", self.text)
        self.assertIsNone(re.search(r"(?i)\bgh_token\b", self.text))
        self.assertIsNone(re.search(r"(?m)^\s*env:\s*\n\s*GH_TOKEN:", self.text))
        self.assertIn('RUSTUP_TOOLCHAIN: "1.94.1"', self.text)
        self.assertIn("runs-on: ubuntu-24.04", self.text)
        self.assertIn("timeout-minutes:", self.text)
        self.assertIn("concurrency:", self.text)
        self.assertIn("cargo build --locked --release", self.text)
        self.assertIn("--version", self.text)
        self.assertIn("build-dry-run.py --mode dry-run --output-dir", self.text)
        self.assertIn("git_verified", self.text)
        self.assertIn('"source_root" not in record', self.text)
        self.assertIn('"invocation" not in record', self.text)
        self.assertIn(
            '["BUILD-INFO.json", "INSTALL.md", "LICENSE-MIT", "THIRD_PARTY_LICENSES.md", "astatine"]',
            self.text,
        )

    def test_builder_gate_constants_match_real_provenance_inventory(self) -> None:
        import importlib.util as _ilu

        gate_path = SOURCE_ROOT / "support" / "release" / "gate.py"
        spec = _ilu.spec_from_file_location("gate_check", gate_path)
        assert spec is not None and spec.loader is not None
        gate_mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(gate_mod)
        gate = gate_mod.load_gate(SOURCE_ROOT)
        # Real checkout now carries owner-authorized release intent; dry-run
        # must accept it via gate.py without claiming final publication.
        self.assertEqual(gate["state"], "release-intent-authorized")
        self.assertTrue(gate["release_intent_authorized"])
        self.assertFalse(gate["publication_authorized"])
        self.assertFalse(gate["final_release_controls_complete"])
        self.assertEqual(gate["source_status"], "RELEASE-INTENT-AUTHORIZED")
        self.assertEqual(gate["binary_status"], "RELEASE-INTENT-AUTHORIZED")
        self.assertEqual(gate["blocking_open"], [])
        self.assertIn("x86_64-unknown-linux-gnu", gate["targets"])

    def test_attestation_pin_absent_and_workflow_has_no_attestation(self) -> None:
        pin_path = SOURCE_ROOT / "support" / "release" / "attestation-action-pin.json"
        self.assertFalse(
            pin_path.exists(),
            "attestation pin evidence must be absent once attestation dispatch is removed",
        )
        self.assertNotIn("attest-build-provenance", self.text)
        self.assertNotIn("gh attestation verify", self.text)
        self.assertNotIn("attestations: write", self.text)
        self.assertNotIn("id-token: write", self.text)

    def test_readme_requires_green_ci_and_denies_e06_sufficiency(self) -> None:
        readme = (SOURCE_ROOT / "support" / "release" / "README.md").read_text(encoding="utf-8")
        # New lane README distinguishes the nonpublishing dry-run from the
        # authorized dual-platform release and records external gating.
        self.assertIn("Nonpublishing", readme)
        self.assertIn("build-release.py", readme)
        self.assertIn("externally gated", readme)
        self.assertIn("v0.1.0-testnet.4", readme)
        self.assertIn("macOS ARM64", readme)

    def test_workflow_header_requires_green_ci(self) -> None:
        self.assertIn("green Rust CI", self.text)
        self.assertIn("exact dispatched commit", self.text)

    def test_only_expected_workflows_exist(self) -> None:
        workflows = sorted(
            [p.name for p in (SOURCE_ROOT / ".github" / "workflows").glob("*.yml")]
            + [p.name for p in (SOURCE_ROOT / ".github" / "workflows").glob("*.yaml")]
        )
        self.assertEqual(workflows, ["ci.yml", "linux-native-qualification.yml", "linux-release-dry-run.yml", "release.yml"])
        ci_text = (SOURCE_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertNotIn("workflow_dispatch", ci_text)

    def test_readme_distinguishes_prerequisite_from_executed_steps(self) -> None:
        readme = (SOURCE_ROOT / "support" / "release" / "README.md").read_text(encoding="utf-8")
        self.assertIn("never becomes a release path", readme)
        self.assertIn("build-release.py", readme)
        self.assertIn("Local use (offline)", readme)

    @unittest.skipIf(_yaml is None, "PyYAML unavailable; string checks above still apply")
    def test_yaml_structure(self) -> None:
        parsed = _yaml.safe_load(self.text)
        assert_workflow_structure(parsed)

    def test_yaml_structure_rejects_violations(self) -> None:
        base = {
            True: {"workflow_dispatch": None},
            "jobs": {
                "linux-release-dry-run": {
                    "permissions": {
                        "contents": "read",
                    },
                    "steps": [
                        {
                            "run": "python3 -B support/release/build-dry-run.py --mode dry-run --output-dir \"$RUNNER_TEMP/out\""
                        }
                    ],
                }
            },
        }
        import copy as _copy

        assert_workflow_structure(_copy.deepcopy(base))
        bad_on = _copy.deepcopy(base)
        bad_on[True] = {"workflow_dispatch": None, "push": {"branches": ["main"]}}
        with self.assertRaises(AssertionError):
            assert_workflow_structure(bad_on)
        bad_perms = _copy.deepcopy(base)
        bad_perms["jobs"]["linux-release-dry-run"]["permissions"] = {
            "contents": "read",
            "id-token": "write",
        }
        with self.assertRaises(AssertionError):
            assert_workflow_structure(bad_perms)
        bad_attest_perms = _copy.deepcopy(base)
        bad_attest_perms["jobs"]["linux-release-dry-run"]["permissions"] = {
            "contents": "read",
            "attestations": "write",
        }
        with self.assertRaises(AssertionError):
            assert_workflow_structure(bad_attest_perms)
        bad_env = _copy.deepcopy(base)
        bad_env["jobs"]["linux-release-dry-run"]["environment"] = "testnet-release-signing"
        with self.assertRaises(AssertionError):
            assert_workflow_structure(bad_env)
        bad_attest_step = _copy.deepcopy(base)
        bad_attest_step["jobs"]["linux-release-dry-run"]["steps"] = [
            {"uses": "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8"}
        ]
        with self.assertRaises(AssertionError):
            assert_workflow_structure(bad_attest_step)
        bad_binding = _copy.deepcopy(base)
        bad_binding["jobs"]["linux-release-dry-run"]["steps"] = [
            {"run": "gh attestation verify artifact -R o/r --signer-workflow w"}
        ]
        with self.assertRaises(AssertionError):
            assert_workflow_structure(bad_binding)
        for command in (
            "cargo publish",
            "npm publish",
            "docker push example/image:tag",
            "git push origin main",
            "gh release create v1",
            "gh api repos/o/r/releases",
            "twine upload dist/*",
        ):
            bad_run = _copy.deepcopy(base)
            bad_run["jobs"]["linux-release-dry-run"]["steps"] = [{"run": command}]
            with self.assertRaises(AssertionError, msg=command):
                assert_workflow_structure(bad_run)
        benign = _copy.deepcopy(base)
        benign["jobs"]["linux-release-dry-run"]["steps"] = [
            {
                "run": "echo built # release notes for reviewers\n"
                "python3 -B support/release/build-dry-run.py --mode dry-run --output-dir \"$RUNNER_TEMP/out\""
            }
        ]
        assert_workflow_structure(benign)

    def test_module_file_exists(self) -> None:
        self.assertTrue(DRY_RUN_PATH.is_file())


class DryRunAuthorizedGateTests(unittest.TestCase):
    """Dry-run accepts the authorized licensing gate but never publishes."""

    def setUp(self) -> None:
        self.source_tmp = tempfile.TemporaryDirectory(prefix="astatine-dryrun-auth-src-")
        self.out_tmp = tempfile.TemporaryDirectory(prefix="astatine-dryrun-auth-out-")
        self.root = Path(self.source_tmp.name)
        self.out = Path(self.out_tmp.name) / "out"
        self.toolchain_patch = mock.patch.object(
            DRY_RUN, "observed_toolchain", return_value=LEGIT_RUSTC_LINE
        )
        self.toolchain_patch.start()
        self.cargo_patch = mock.patch.object(
            DRY_RUN, "observed_cargo_version", return_value=LEGIT_CARGO_LINE
        )
        self.cargo_patch.start()
        self.write_authorized_tree()
        (self.root / ".gitignore").write_text("target/\n", encoding="utf-8")
        init_git_repo(self.root)

    def tearDown(self) -> None:
        self.cargo_patch.stop()
        self.toolchain_patch.stop()
        self.source_tmp.cleanup()
        self.out_tmp.cleanup()

    def write_authorized_tree(self) -> None:
        # Copy the real release-intent gate (provenance + inventory + license
        # evidence) so the synthetic tree carries substantive license files
        # with matching hashes, then add the fake build inputs.
        for rel in (
            "tests/fixtures/PROVENANCE.json",
            "tests/fixtures/README.md",
            "support/release/distribution-inventory.json",
            "tests/fixtures/LICENSE-APACHE-2.0.txt",
            "tests/fixtures/LICENSE-MIT.txt",
            "tests/fixtures/NOTICE",
            "tests/fixtures/OPENZEPPELIN_LICENSE.txt",
            "support/update-evm-test-fixtures.py",
            "support/update-genesis-coordinator-fixture.py",
            "support/release/RELEASE_NOTES-v0.1.0-testnet.1.md",
            "support/release/RELEASE_NOTES-v0.1.0-testnet.2.md",
            "support/release/RELEASE_NOTES-v0.1.0-testnet.4.md",
        ):
            src = SOURCE_ROOT / rel
            dest = self.root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
        (self.root / "target" / "release").mkdir(parents=True, exist_ok=True)
        (self.root / "target" / "release" / "astatine").write_bytes(FAKE_ELF_BINARY)
        (self.root / "LICENSE-MIT").write_text("test MIT\n", encoding="utf-8")
        (self.root / "THIRD_PARTY_LICENSES.md").write_text("test notices\n", encoding="utf-8")
        (self.root / "Cargo.toml").write_text(
            TEST_CARGO_TOML.replace('0.1.0-testnet.0', '0.1.0-testnet.4'), encoding="utf-8"
        )
        (self.root / "Cargo.lock").write_bytes(TEST_LOCK_BYTES)
        (self.root / "support" / "release-repository.txt").write_text(TEST_REPOSITORY, encoding="utf-8")

    def test_authorized_gate_still_builds_dry_run_without_publication(self) -> None:
        result = DRY_RUN.run(source_root=self.root, output_dir=self.out, mode="dry-run")
        self.assertEqual(result["members"], EXPECTED_MEMBERS)
        self.assertFalse(result["publication_authorized"])
        self.assertTrue(result["release_intent_authorized"])
        self.assertFalse(result["final_release_controls_complete"])
        self.assertEqual(
            result["rights_decision"],
            "OWNER-AUTHORIZED RELEASE INTENT \u2014 project owner authorized first-party "
            "source and binary distribution intent for v0.1.0-testnet.4 under the "
            "explicitly documented owner self-approval policy; technical NOTICE review "
            "recorded; final release controls outstanding; not a legal conclusion, not "
            "independent review, and not a separate approval.",
        )
        self.assertEqual(result["blocking_open"], [])
        record = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        self.assertIs(record["publication_authorized"], False)
        self.assertEqual(record["mode"], "dry-run")
        self.assertTrue(record["artifact"]["filename"].endswith(".dry-run.tar.gz"))
        # The authorized licensing gate necessarily mentions attestation
        # requirements for the external release workflow, but the dry-run must
        # prove no attestation/upload/release action occurred.
        dumped = json.dumps(record)
        self.assertNotIn("gh release", dumped)
        self.assertNotIn("attest-build-provenance", dumped)
        self.assertNotIn("id-token", dumped)
        self.assertNotIn("upload-artifact", dumped)
        self.assertIn("no publication, upload, release asset, tag, release", dumped)
        with tarfile.open(result["artifact_path"], mode="r") as tar:
            names = sorted(tar.getnames())
            self.assertEqual(names, EXPECTED_MEMBERS)
            build_info = json.loads(tar.extractfile("BUILD-INFO.json").read().decode("utf-8"))
        self.assertIs(build_info["publication_authorized"], False)
        self.assertIn("dry-run", build_info["distribution"])

    def test_authorized_dry_run_deterministic(self) -> None:
        first = DRY_RUN.run(source_root=self.root, output_dir=self.out, mode="dry-run")
        first_bytes = Path(first["artifact_path"]).read_bytes()
        second_out = Path(self.out_tmp.name) / "out-two"
        second = DRY_RUN.run(source_root=self.root, output_dir=second_out, mode="dry-run")
        self.assertEqual(first_bytes, Path(second["artifact_path"]).read_bytes())

    def test_authorized_dry_run_release_mode_still_fails(self) -> None:
        with self.assertRaisesRegex(DRY_RUN.DryRunError, "no release path|not authorized"):
            DRY_RUN.run(source_root=self.root, output_dir=self.out, mode="release")


if __name__ == "__main__":
    unittest.main()
