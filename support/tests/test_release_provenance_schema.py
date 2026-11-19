#!/usr/bin/env python3
"""Regression for v0.1.0-testnet.2 live packaging failure (run 44283340169).

The builder nested ``rights_decision`` under ``gate`` while the release
workflow ``release-package`` and ``release-draft`` inline semantic validators
require top-level ``prov.get("rights_decision")``. This test runs the real
``support/release/build-release.py`` and then executes the ACTUAL workflow
inline Python validators (extracted from ``.github/workflows/release.yml``),
not text markers or mocks. It fails closed if the schema mismatches.

Never touches the real tree, network, wallets, or releases. Run with
``python3 -B``.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
BUILDER_PATH = ROOT / "support" / "release" / "build-release.py"

TAG = "v0.1.0-testnet.5"
COMMIT_PLACEHOLDER = "0123456789abcdef0123456789abcdef01234567"
LEGIT_RUSTC_LINE = "rustc 1.94.1 (e408947bf 2026-03-25)"
LEGIT_CARGO_LINE = "cargo 1.94.1 (29ea6fb6a 2026-03-24)"
REPO_ID = "123456789"

FAKE_ELF = (
    b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    + (2).to_bytes(2, "little") + (62).to_bytes(2, "little")
    + (1).to_bytes(4, "little") + bytes(40)
)
FAKE_MACHO = (
    b"\xcf\xfa\xed\xfe"
    + (0x0100000C).to_bytes(4, "little")
    + (0).to_bytes(4, "little")
    + (2).to_bytes(4, "little")
    + bytes(20)
)
FAKE_PE = (
    b"MZ" + bytes(58) + (64).to_bytes(4, "little")
    + b"PE\x00\x00" + (0x8664).to_bytes(2, "little") + bytes(20) + bytes(64)
)


def load_builder():
    spec = importlib.util.spec_from_file_location("release_builder_regression", BUILDER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load builder")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


BUILDER = load_builder()


def init_repo(root: pathlib.Path, tag: str = TAG) -> str:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "t@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "t"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "release"], check=True)
    subprocess.run(["git", "-C", str(root), "tag", tag], check=True)
    out = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
    return out.stdout.strip()


def extract_workflow_provenance_validators() -> tuple[str, str]:
    """Return (package_validator, draft_validator) as raw Python source.

    Extracts the ACTUAL inline ``python3 - ... <<'PY'`` blocks that enforce
    ``provenance field rights_decision`` in both jobs. Fails if the
    extraction is ambiguous.
    """
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    # Package: step contains two python heredocs (remote tag + provenance).
    # We need the one that checks rights_decision.
    pkg_steps = workflow["jobs"]["release-package"]["steps"]
    pkg_run = next(s["run"] for s in pkg_steps if s.get("name") == "Verify remote tag and provenance before archive attestation")
    draft_steps = workflow["jobs"]["release-draft"]["steps"]
    draft_run = next(s["run"] for s in draft_steps if s.get("name") == "Verify release provenance semantics")
    def split_heredocs(run: str) -> list[str]:
        parts = run.split("<<'PY'\n")
        scripts: list[str] = []
        for tail in parts[1:]:
            if "\nPY\n" not in tail and not tail.rstrip().endswith("\nPY"):
                continue
            # Heredoc ends at line containing only PY
            lines = tail.splitlines()
            collected: list[str] = []
            for line in lines:
                if line.strip() == "PY":
                    break
                collected.append(line)
            scripts.append("\n".join(collected))
        return scripts
    pkg_scripts = split_heredocs(pkg_run)
    draft_scripts = split_heredocs(draft_run)
    pkg_candidates = [s for s in pkg_scripts if "provenance field rights_decision missing or empty" in s]
    draft_candidates = [s for s in draft_scripts if "provenance field rights_decision missing or empty" in s]
    if len(pkg_candidates) != 1:
        raise AssertionError(f"expected exactly one package provenance validator, got {len(pkg_candidates)}")
    if len(draft_candidates) != 1:
        raise AssertionError(f"expected exactly one draft provenance validator, got {len(draft_candidates)}")
    pkg = pkg_candidates[0]
    draft = draft_candidates[0]
    # Sanity: both must read top-level rights_decision, not gate nested.
    for label, script in (("package", pkg), ("draft", draft)):
        if 'prov.get("rights_decision")' not in script:
            raise AssertionError(f"{label} validator does not read top-level rights_decision")
        if 'prov.get("gate", {}).get("rights_decision")' in script:
            raise AssertionError(f"{label} validator must not read nested gate rights_decision")
    return pkg, draft


class ReleaseProvenanceSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.src_tmp = tempfile.TemporaryDirectory(prefix="astatine-prov-schema-src-")
        self.out_tmp = tempfile.TemporaryDirectory(prefix="astatine-prov-schema-out-")
        self.bin_tmp = tempfile.TemporaryDirectory(prefix="astatine-prov-schema-bin-")
        self.root = pathlib.Path(self.src_tmp.name)
        for rel in (
            "tests/fixtures/PROVENANCE.json",
            "tests/fixtures/README.md",
            "support/release/distribution-inventory.json",
            "tests/fixtures/LICENSE-APACHE-2.0.txt",
            "tests/fixtures/LICENSE-MIT.txt",
            "tests/fixtures/NOTICE",
            "tests/fixtures/OPENZEPPELIN_LICENSE.txt",
            "Cargo.toml",
            "Cargo.lock",
            "LICENSE-MIT",
            "THIRD_PARTY_LICENSES.md",
            "support/release-repository.txt",
            "rust-toolchain.toml",
            "support/update-evm-test-fixtures.py",
            "support/update-genesis-coordinator-fixture.py",
            "support/release/RELEASE_NOTES-v0.1.0-testnet.1.md",
            "support/release/RELEASE_NOTES-v0.1.0-testnet.2.md",
            "support/release/RELEASE_NOTES-v0.1.0-testnet.5.md",
        ):
            src = ROOT / rel
            if not src.is_file():
                continue
            dest = self.root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
        self.macos_bin = pathlib.Path(self.bin_tmp.name) / "macos-astatine"
        self.linux_bin = pathlib.Path(self.bin_tmp.name) / "linux-astatine"
        self.windows_bin = pathlib.Path(self.bin_tmp.name) / "windows-astatine.exe"
        self.macos_bin.write_bytes(FAKE_MACHO + b"\x00" * 64)
        self.linux_bin.write_bytes(FAKE_ELF)
        self.windows_bin.write_bytes(FAKE_PE)
        (self.root / ".gitignore").write_text("target/\n", encoding="utf-8")
        self.commit = init_repo(self.root, TAG)
        self.out = pathlib.Path(self.out_tmp.name) / "out"

    def tearDown(self) -> None:
        self.src_tmp.cleanup()
        self.out_tmp.cleanup()
        self.bin_tmp.cleanup()

    def run_builder(self) -> dict:
        return BUILDER.run(
            source_root=self.root,
            output_dir=self.out,
            tag=TAG,
            repository_id=REPO_ID,
            macos_binary=self.macos_bin,
            linux_binary=self.linux_bin,
            windows_binary=self.windows_bin,
            rustc_version=LEGIT_RUSTC_LINE,
            cargo_version=LEGIT_CARGO_LINE,
        )

    def test_builder_emits_top_level_rights_decision(self) -> None:
        result = self.run_builder()
        self.assertEqual(result["tag"], TAG)
        prov = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        # Top-level must exist for workflow validators.
        self.assertIn("rights_decision", prov)
        self.assertIsInstance(prov["rights_decision"], str)
        self.assertTrue(prov["rights_decision"].strip())
        # Nested gate record preserved for backward compatibility.
        self.assertIn("gate", prov)
        self.assertEqual(prov["gate"].get("rights_decision"), prov["rights_decision"])
        lowered = prov["rights_decision"].lower()
        self.assertIn("owner-authorized release intent", lowered)
        self.assertIn("final release controls outstanding", lowered)
        self.assertNotIn("publication authorized", lowered)
        self.assertNotIn("release approver", lowered)

    def test_workflow_package_and_draft_validators_accept_real_builder_output(self) -> None:
        self.run_builder()
        pkg_script, draft_script = extract_workflow_provenance_validators()
        prov_path = self.out / "release-provenance.json"
        sums_path = self.out / "SHA256SUMS"
        # Workflow package validator args: prov, sums, tag, sha, repo_id
        # Draft validator args: prov, sums, notes, tag, sha, repo_id
        # Provide release-notes.md as workflow does (copied from tagged notes).
        notes_src = self.root / "support" / "release" / f"RELEASE_NOTES-{TAG}.md"
        notes_path = self.out / "release-notes.md"
        shutil.copy2(notes_src, notes_path)
        # Package validator (real inline code)
        pkg_cmd = [sys.executable, "-", str(prov_path), str(sums_path), TAG, self.commit, REPO_ID]
        pkg_proc = subprocess.run(pkg_cmd, input=pkg_script.encode("utf-8"), capture_output=True)
        self.assertEqual(
            pkg_proc.returncode, 0,
            f"package validator rejected real builder output: stdout={pkg_proc.stdout.decode()!r} stderr={pkg_proc.stderr.decode()!r}",
        )
        self.assertIn(b"release provenance semantics verified", pkg_proc.stdout + pkg_proc.stderr)
        # Draft validator (real inline code)
        draft_cmd = [sys.executable, "-", str(prov_path), str(sums_path), str(notes_path), TAG, self.commit, REPO_ID]
        draft_proc = subprocess.run(draft_cmd, input=draft_script.encode("utf-8"), capture_output=True)
        self.assertEqual(
            draft_proc.returncode, 0,
            f"draft validator rejected real builder output: stdout={draft_proc.stdout.decode()!r} stderr={draft_proc.stderr.decode()!r}",
        )
        self.assertIn(b"release provenance semantics verified", draft_proc.stdout + draft_proc.stderr)

    def test_validators_reject_missing_top_level_rights_decision(self) -> None:
        """Prove the regression would have caught the .2 failure.

        Removes top-level rights_decision (simulating the .2 builder) while
        keeping the nested gate record; both real validators must fail closed.
        """
        self.run_builder()
        pkg_script, draft_script = extract_workflow_provenance_validators()
        prov_path = self.out / "release-provenance.json"
        sums_path = self.out / "SHA256SUMS"
        data = json.loads(prov_path.read_text(encoding="utf-8"))
        self.assertIn("rights_decision", data)
        del data["rights_decision"]
        # Keep nested gate for the .2 shape.
        self.assertIn("gate", data)
        self.assertIn("rights_decision", data["gate"])
        prov_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        notes_src = self.root / "support" / "release" / f"RELEASE_NOTES-{TAG}.md"
        notes_path = self.out / "release-notes.md"
        shutil.copy2(notes_src, notes_path)
        pkg_cmd = [sys.executable, "-", str(prov_path), str(sums_path), TAG, self.commit, REPO_ID]
        pkg_proc = subprocess.run(pkg_cmd, input=pkg_script.encode("utf-8"), capture_output=True)
        self.assertNotEqual(pkg_proc.returncode, 0, "package validator must reject missing top-level rights_decision")
        self.assertIn(b"provenance field rights_decision missing or empty", pkg_proc.stderr)
        draft_cmd = [sys.executable, "-", str(prov_path), str(sums_path), str(notes_path), TAG, self.commit, REPO_ID]
        draft_proc = subprocess.run(draft_cmd, input=draft_script.encode("utf-8"), capture_output=True)
        self.assertNotEqual(draft_proc.returncode, 0, "draft validator must reject missing top-level rights_decision")
        self.assertIn(b"provenance field rights_decision missing or empty", draft_proc.stderr)


if __name__ == "__main__":
    unittest.main()
