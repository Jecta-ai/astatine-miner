#!/usr/bin/env python3
"""Offline tests for support/release/build-release.py.

Uses temp source trees with the real authorized gate plus synthetic Mach-O/ELF
headers. Never touches the real tree, network, wallets, or real builds. Run
with ``python3 -B``.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[2]
BUILDER_PATH = SOURCE_ROOT / "support" / "release" / "build-release.py"

MACOS_ROOT = "astatine-v0.1.0-testnet.1-macos-arm64"
LINUX_ROOT = "astatine-v0.1.0-testnet.1-linux-x86_64"
MACOS_ARCHIVE = "astatine-v0.1.0-testnet.1-macos-arm64.tar.gz"
LINUX_ARCHIVE = "astatine-v0.1.0-testnet.1-linux-x86_64.tar.gz"
EXPECTED_MACOS_MEMBERS = sorted([
    f"{MACOS_ROOT}/astatine",
    f"{MACOS_ROOT}/LICENSE-MIT",
    f"{MACOS_ROOT}/THIRD_PARTY_LICENSES.md",
    f"{MACOS_ROOT}/BUILD-INFO.json",
    f"{MACOS_ROOT}/INSTALL.md",
])
EXPECTED_LINUX_MEMBERS = sorted([
    f"{LINUX_ROOT}/astatine",
    f"{LINUX_ROOT}/LICENSE-MIT",
    f"{LINUX_ROOT}/THIRD_PARTY_LICENSES.md",
    f"{LINUX_ROOT}/BUILD-INFO.json",
    f"{LINUX_ROOT}/INSTALL.md",
])
TAG = "v0.1.0-testnet.1"

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


def load_builder():
    spec = importlib.util.spec_from_file_location("release_builder", BUILDER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load builder")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


BUILDER = load_builder()


def init_repo(root: Path, tag: str = TAG) -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "t@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "t"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "release"], check=True)
    subprocess.run(["git", "-C", str(root), "tag", tag], check=True)


class ReleaseBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.src_tmp = tempfile.TemporaryDirectory(prefix="astatine-rel-src-")
        self.out_tmp = tempfile.TemporaryDirectory(prefix="astatine-rel-out-")
        self.bin_tmp = tempfile.TemporaryDirectory(prefix="astatine-rel-bin-")
        self.root = Path(self.src_tmp.name)
        # Copy real authorized gate + evidence.
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
        ):
            src = SOURCE_ROOT / rel
            if not src.is_file():
                continue
            dest = self.root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
        self.macos_bin = Path(self.bin_tmp.name) / "macos-astatine"
        self.linux_bin = Path(self.bin_tmp.name) / "linux-astatine"
        self.macos_bin.write_bytes(FAKE_MACHO + b"\x00" * 64)
        self.linux_bin.write_bytes(FAKE_ELF)
        (self.root / ".gitignore").write_text("target/\n", encoding="utf-8")
        init_repo(self.root)
        self.out = Path(self.out_tmp.name) / "out"

    def tearDown(self) -> None:
        self.src_tmp.cleanup()
        self.out_tmp.cleanup()
        self.bin_tmp.cleanup()

    def run_builder(self, **overrides):
        kwargs = dict(
            source_root=self.root,
            output_dir=self.out,
            tag=TAG,
            repository_id="123456789",
            macos_binary=self.macos_bin,
            linux_binary=self.linux_bin,
        )
        kwargs.update(overrides)
        return BUILDER.run(**kwargs)

    def test_success_exact_layout_deterministic(self) -> None:
        result = self.run_builder()
        self.assertTrue(result["release_intent_authorized"])
        self.assertFalse(result["publication_authorized"])
        self.assertFalse(result["final_release_controls_complete"])
        self.assertEqual(result["tag"], TAG)
        # Two archives with root-prefixed five members.
        by_name = {e["filename"]: e for e in result["archives"]}
        self.assertEqual(sorted(by_name), sorted([MACOS_ARCHIVE, LINUX_ARCHIVE]))
        for entry in result["archives"]:
            members = sorted(m["archive_path"] for m in entry["members"])
            if entry["filename"] == MACOS_ARCHIVE:
                self.assertEqual(members, EXPECTED_MACOS_MEMBERS)
            else:
                self.assertEqual(members, EXPECTED_LINUX_MEMBERS)
            # Modes preserved inside root.
            for m in entry["members"]:
                if m["archive_path"].endswith("/astatine"):
                    self.assertEqual(m["mode"], "0o755")
                else:
                    self.assertEqual(m["mode"], "0o644")
        # Deterministic bytes across runs.
        first = {e["filename"]: Path(self.out / e["filename"]).read_bytes() for e in result["archives"]}
        second_out = Path(self.out_tmp.name) / "out-two"
        BUILDER.run(
            source_root=self.root,
            output_dir=second_out,
            tag=TAG,
            repository_id="123456789",
            macos_binary=self.macos_bin,
            linux_binary=self.linux_bin,
        )
        for e in result["archives"]:
            self.assertEqual(first[e["filename"]], (second_out / e["filename"]).read_bytes())
        # Tar listing shows single root dir; workflow fixture check still works.
        for archive, root in ((MACOS_ARCHIVE, MACOS_ROOT), (LINUX_ARCHIVE, LINUX_ROOT)):
            data = (self.out / archive).read_bytes()
            with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
                names = tar.getnames()
                self.assertEqual(sorted(names), sorted(
                    [f"{root}/astatine", f"{root}/LICENSE-MIT", f"{root}/THIRD_PARTY_LICENSES.md", f"{root}/BUILD-INFO.json", f"{root}/INSTALL.md"]
                ))
                # Simulate workflow `tar -tzf` fixture check with prefix.
                listing = "\n".join(names)
                self.assertNotIn("tests/fixtures", listing)
                self.assertNotIn("PROVENANCE.json", listing)
                for m in tar.getmembers():
                    self.assertEqual(m.mtime, 0)
                    self.assertEqual(m.uid, 0)
                    self.assertFalse(m.issym() or m.islnk())
        # SHA256SUMS and provenance.
        sums = (self.out / "SHA256SUMS").read_text(encoding="utf-8")
        for e in result["archives"]:
            self.assertIn(e["sha256"], sums)
            self.assertIn(e["filename"], sums)
        prov = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        self.assertTrue(prov["release_intent_authorized"])
        self.assertFalse(prov["publication_authorized"])
        self.assertFalse(prov["final_release_controls_complete"])
        self.assertEqual(prov["tag"], TAG)
        self.assertEqual(len(prov["archives"]), 2)
        dumped = json.dumps(prov)
        self.assertNotIn('"publication_authorized": true', dumped)
        self.assertNotIn(str(self.root.resolve()), dumped)
        self.assertNotIn(str(self.out.resolve()), dumped)
        self.assertNotIn("--macos-binary", dumped)
        self.assertNotIn("--linux-binary", dumped)

    def test_install_safety_no_sudo_no_xattr(self) -> None:
        result = self.run_builder()
        for e in result["archives"]:
            with tarfile.open(self.out / e["filename"], mode="r") as tar:
                install = tar.extractfile(
                    f"{MACOS_ROOT}/INSTALL.md" if "macos" in e["filename"] else f"{LINUX_ROOT}/INSTALL.md"
                ).read().decode("utf-8")
            lowered = install.lower()
            if "macos" in e["filename"]:
                # Ad-hoc only, NOT Developer ID/notarized (macOS only).
                self.assertIn("ad-hoc", lowered)
                self.assertIn("NOT Developer ID", install)
                self.assertIn("NOT notarized", install)
                # Gatekeeper: stop and retain, with an explicit prohibition.
                self.assertIn("stop and retain", lowered)
                self.assertIn("Do NOT disable Gatekeeper", install)
            else:
                # Linux platform notes instead of macOS signing notes.
                self.assertIn("glibc", lowered)
                self.assertIn("secret service", lowered)
                # Linux must not claim Apple signing.
                self.assertNotIn("ad-hoc", lowered)
                self.assertNotIn("developer id", lowered)
                self.assertNotIn("notarized", lowered)
            # No imperative instructions/commands to weaken system policy or
            # escalate privileges: reject commands, not the word inside a
            # "Do NOT ..." prohibition sentence.
            self.assertNotIn("xattr -d", install)
            self.assertNotIn("spctl --master-disable", install)
            self.assertNotIn("csrutil disable", install)
            for line in install.splitlines():
                stripped = line.strip()
                lowered_line = stripped.lower()
                # Reject direct sudo invocations, allowing prose such as
                # "never require sudo" / "never with sudo".
                self.assertFalse(
                    lowered_line.startswith("sudo "),
                    f"sudo invocation found: {line!r}",
                )
                self.assertNotIn("`sudo ", lowered_line)
            # User-owned path, never sudo.
            self.assertIn("$HOME/.local/bin", install)
            self.assertIn("never require sudo", lowered)
            self.assertNotIn("/usr/local/bin", install)
            # Attestation instructions preserved.
            self.assertIn("build-provenance", install)
            self.assertIn("isImmutable", install)
            # Testnet only, no mainnet.
            self.assertIn("Testnet only", install)
            self.assertNotIn("mainnet deployment", install.lower().replace("no mainnet", ""))
        # Platform checksum commands: single-platform filtered rows using the
        # actual archive name; never a full-file check for one platform.
        with tarfile.open(self.out / MACOS_ARCHIVE, mode="r") as tar:
            mac_install = tar.extractfile(f"{MACOS_ROOT}/INSTALL.md").read().decode("utf-8")
        with tarfile.open(self.out / LINUX_ARCHIVE, mode="r") as tar:
            lin_install = tar.extractfile(f"{LINUX_ROOT}/INSTALL.md").read().decode("utf-8")
        self.assertIn(f'grep -F "  {MACOS_ARCHIVE}" SHA256SUMS | shasum -a 256 -c -', mac_install)
        self.assertIn(f'grep -F "  {LINUX_ARCHIVE}" SHA256SUMS | sha256sum -c -', lin_install)
        self.assertNotIn("shasum -a 256 -c SHA256SUMS", mac_install)
        self.assertNotIn("sha256sum -c SHA256SUMS", lin_install)

    def test_build_info_record(self) -> None:
        result = self.run_builder()
        for e in result["archives"]:
            root = MACOS_ROOT if "macos" in e["filename"] else LINUX_ROOT
            with tarfile.open(self.out / e["filename"], mode="r") as tar:
                info = json.loads(tar.extractfile(f"{root}/BUILD-INFO.json").read().decode("utf-8"))
            self.assertEqual(info["schema"], "astatine-build-info/v1")
            self.assertTrue(info["release_intent_authorized"])
            self.assertFalse(info["publication_authorized"])
            self.assertFalse(info["final_release_controls_complete"])
            self.assertIn("rights_decision", info["rights_gate"])
            self.assertNotIn("publication_decision", info["rights_gate"])
            self.assertIn("release_intent_authorization", info["rights_gate"])
            self.assertIn("technical_notice_review", info["rights_gate"])
            self.assertNotIn('"publication_authorized": true', json.dumps(info))
            self.assertIn("workflow-built", info["binary_build_linkage"])
            self.assertIn("attestation", info["binary_build_linkage"])
            self.assertIn("not claimed", info["binary_build_linkage"])
            self.assertEqual(
                info["build"]["toolchain_observation"],
                "pinned expected lines; CI build jobs install and assert Rust/Cargo 1.94.1; this offline packager does not independently re-observe the toolchain",
            )

    def test_draft_only_release_controls(self) -> None:
        result = self.run_builder()
        prov = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(
            prov["gate"]["release_controls"],
            "DRAFT-ONLY \u2014 MANUAL PUBLICATION AFTER EXTERNAL IMMUTABLE-SETTING VERIFICATION",
        )
        for e in result["archives"]:
            root = MACOS_ROOT if "macos" in e["filename"] else LINUX_ROOT
            with tarfile.open(self.out / e["filename"], mode="r") as tar:
                info = json.loads(tar.extractfile(f"{root}/BUILD-INFO.json").read().decode("utf-8"))
            self.assertEqual(info["release_controls"]["publication_mode"], "draft-only-manual-publish")
            self.assertTrue(info["release_controls"]["manual_publish_required"])
            self.assertTrue(info["release_controls"]["immutable_setting_admin_verification_required"])
            self.assertTrue(info["release_controls"]["immutable_release"])

    def test_external_blockers_cover_writer_restriction_and_rechecks(self) -> None:
        import importlib.util as _ilu

        spec = _ilu.spec_from_file_location("gate_check", SOURCE_ROOT / "support" / "release" / "gate.py")
        assert spec is not None and spec.loader is not None
        gate_mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(gate_mod)
        gate = gate_mod.load_gate(SOURCE_ROOT)
        blockers = gate["release_controls"]["external_blockers"]
        self.assertIn(
            "repository writers and write-capable apps are restricted so only the release owner/admin can publish or modify the draft",
            blockers,
        )
        self.assertIn(
            "owner/admin verifies immutable releases are enabled before dispatch and again immediately before manual publication",
            blockers,
        )
        self.assertIn(
            "release tag is rechecked immediately before manual publication",
            blockers,
        )

    def test_wrong_tag_rejected(self) -> None:
        with self.assertRaises(BUILDER.ReleaseError):
            self.run_builder(tag="v0.1.0-testnet.2")

    def test_tag_version_mismatch_rejected(self) -> None:
        (self.root / "Cargo.toml").write_text(
            (self.root / "Cargo.toml").read_text().replace("0.1.0-testnet.1", "0.1.0-testnet.9"),
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-q", "-m", "bump"], check=True)
        with self.assertRaises(BUILDER.ReleaseError):
            self.run_builder()

    def test_tag_not_at_head_rejected(self) -> None:
        subprocess.run(["git", "-C", str(self.root), "commit", "-q", "--allow-empty", "-m", "ahead"], check=True)
        with self.assertRaisesRegex(BUILDER.ReleaseError, "does not resolve to HEAD"):
            self.run_builder()

    def test_dirty_tree_rejected(self) -> None:
        (self.root / "LICENSE-MIT").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(BUILDER.ReleaseError, "not clean at HEAD"):
            self.run_builder()

    def test_wrong_macho_rejected(self) -> None:
        bad = Path(self.bin_tmp.name) / "bad-macos"
        bad.write_bytes(FAKE_ELF)
        with self.assertRaisesRegex(BUILDER.ReleaseError, "Mach-O"):
            self.run_builder(macos_binary=bad)

    def test_wrong_elf_rejected(self) -> None:
        bad = Path(self.bin_tmp.name) / "bad-linux"
        bad.write_bytes(b"not elf")
        with self.assertRaisesRegex(BUILDER.ReleaseError, "ELF"):
            self.run_builder(linux_binary=bad)

    def test_missing_license_rejected(self) -> None:
        (self.root / "LICENSE-MIT").unlink()
        with self.assertRaises(BUILDER.ReleaseError):
            self.run_builder()

    def test_symlink_binary_rejected(self) -> None:
        link = Path(self.bin_tmp.name) / "link-bin"
        if link.exists() or link.is_symlink():
            link.unlink()
        os.symlink(self.linux_bin, link)
        with self.assertRaisesRegex(BUILDER.ReleaseError, "symlink"):
            self.run_builder(linux_binary=link)

    def test_output_inside_source_rejected(self) -> None:
        with self.assertRaisesRegex(BUILDER.ReleaseError, "outside the source tree"):
            self.run_builder(output_dir=self.root / "out-inside")

    def test_preexisting_output_rejected(self) -> None:
        self.out.mkdir(parents=True)
        (self.out / "SHA256SUMS").write_bytes(b"stale")
        with self.assertRaises(BUILDER.ReleaseError):
            self.run_builder()

    def test_blocked_gate_rejected(self) -> None:
        # Tamper inventory to blocked status; builder must fail closed.
        inv_path = self.root / "support/release/distribution-inventory.json"
        inv = json.loads(inv_path.read_text(encoding="utf-8"))
        inv["schema"] = "astatine-distribution-inventory/v1"
        inv["rights_gate"]["publication_decision"] = "BLOCKED pending review"
        inv_path.write_text(json.dumps(inv, indent=2) + "\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-q", "-m", "block"], check=True)
        with self.assertRaises(BUILDER.ReleaseError):
            self.run_builder()

    def test_no_absolute_paths_in_provenance(self) -> None:
        self.run_builder()
        prov = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        dumped = json.dumps(prov)
        self.assertNotIn(str(self.root.resolve()), dumped)
        for v in (prov.get("repository_id"),):
            self.assertNotIn("/", str(v) if v else "")


if __name__ == "__main__":
    unittest.main()
