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

MACOS_ROOT = "astatine-v0.1.0-testnet.4-macos-arm64"
LINUX_ROOT = "astatine-v0.1.0-testnet.4-linux-x86_64"
MACOS_ARCHIVE = "astatine-v0.1.0-testnet.4-macos-arm64.tar.gz"
WINDOWS_ROOT = "astatine-v0.1.0-testnet.4-windows-x86_64"
WINDOWS_ARCHIVE = "astatine-v0.1.0-testnet.4-windows-x86_64.zip"
LINUX_ARCHIVE = "astatine-v0.1.0-testnet.4-linux-x86_64.tar.gz"
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
EXPECTED_WINDOWS_MEMBERS = sorted([
    f"{WINDOWS_ROOT}/astatine.exe",
    f"{WINDOWS_ROOT}/LICENSE-MIT",
    f"{WINDOWS_ROOT}/THIRD_PARTY_LICENSES.md",
    f"{WINDOWS_ROOT}/BUILD-INFO.json",
    f"{WINDOWS_ROOT}/INSTALL.md",
])
TAG = "v0.1.0-testnet.4"
LEGIT_RUSTC_LINE = "rustc 1.94.1 (e408947bf 2026-03-25)"
LEGIT_CARGO_LINE = "cargo 1.94.1 (29ea6fb6a 2026-03-24)"

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
            "support/update-evm-test-fixtures.py",
            "support/update-genesis-coordinator-fixture.py",
            "support/release/RELEASE_NOTES-v0.1.0-testnet.1.md",
            "support/release/RELEASE_NOTES-v0.1.0-testnet.2.md",
            "support/release/RELEASE_NOTES-v0.1.0-testnet.3.md",
            "support/release/RELEASE_NOTES-v0.1.0-testnet.4.md",
        ):
            src = SOURCE_ROOT / rel
            if not src.is_file():
                continue
            dest = self.root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
        self.macos_bin = Path(self.bin_tmp.name) / "macos-astatine"
        self.linux_bin = Path(self.bin_tmp.name) / "linux-astatine"
        self.windows_bin = Path(self.bin_tmp.name) / "windows-astatine.exe"
        self.macos_bin.write_bytes(FAKE_MACHO + b"\x00" * 64)
        self.linux_bin.write_bytes(FAKE_ELF)
        self.windows_bin.write_bytes(FAKE_PE)
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
            windows_binary=self.windows_bin,
            rustc_version=LEGIT_RUSTC_LINE,
            cargo_version=LEGIT_CARGO_LINE,
        )
        kwargs.update(overrides)
        return BUILDER.run(**kwargs)

    def test_success_exact_layout_deterministic(self) -> None:
        result = self.run_builder()
        self.assertTrue(result["release_intent_authorized"])
        self.assertFalse(result["publication_authorized"])
        self.assertFalse(result["final_release_controls_complete"])
        self.assertEqual(result["tag"], TAG)
        # Three archives with root-prefixed five members, per-target exact.
        by_name = {e["filename"]: e for e in result["archives"]}
        self.assertEqual(sorted(by_name), sorted([MACOS_ARCHIVE, LINUX_ARCHIVE, WINDOWS_ARCHIVE]))
        for entry in result["archives"]:
            members = sorted(m["archive_path"] for m in entry["members"])
            if entry["filename"] == MACOS_ARCHIVE:
                self.assertEqual(members, EXPECTED_MACOS_MEMBERS)
            elif entry["filename"] == LINUX_ARCHIVE:
                self.assertEqual(members, EXPECTED_LINUX_MEMBERS)
            else:
                self.assertEqual(members, EXPECTED_WINDOWS_MEMBERS)
            # Modes preserved inside root, per-target exact (never shared).
            for m in entry["members"]:
                if m["archive_path"].endswith("/astatine") or m["archive_path"].endswith("/astatine.exe"):
                    self.assertEqual(m["mode"], "0o755")
                else:
                    self.assertEqual(m["mode"], "0o644")
            # Per-target exact: Unix must not contain exe, Windows must not contain bare astatine.
            if entry["filename"] == WINDOWS_ARCHIVE:
                self.assertNotIn(f"{WINDOWS_ROOT}/astatine", [x for x in members if not x.endswith(".exe")])
            else:
                self.assertFalse(any(x.endswith("astatine.exe") for x in members))
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
            windows_binary=self.windows_bin,
            rustc_version=LEGIT_RUSTC_LINE,
            cargo_version=LEGIT_CARGO_LINE,
        )
        for e in result["archives"]:
            self.assertEqual(first[e["filename"]], (second_out / e["filename"]).read_bytes())
        # Archive listing shows single root dir; workflow fixture check still works (tar for Unix, zip for Windows).
        import zipfile
        for archive, root, binary_name in ((MACOS_ARCHIVE, MACOS_ROOT, "astatine"), (LINUX_ARCHIVE, LINUX_ROOT, "astatine"), (WINDOWS_ARCHIVE, WINDOWS_ROOT, "astatine.exe")):
            data = (self.out / archive).read_bytes()
            if archive.endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(data), mode="r") as zf:
                    names = zf.namelist()
                    self.assertEqual(sorted(names), sorted(
                        [f"{root}/{binary_name}", f"{root}/LICENSE-MIT", f"{root}/THIRD_PARTY_LICENSES.md", f"{root}/BUILD-INFO.json", f"{root}/INSTALL.md"]
                    ))
                    listing = "\n".join(names)
                    self.assertNotIn("tests/fixtures", listing)
                    self.assertNotIn("PROVENANCE.json", listing)
                    self.assertNotIn("\\", listing)
                    for info in zf.infolist():
                        self.assertFalse(info.is_dir())
                        self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0))
                        mode = (info.external_attr >> 16) & 0o777
                        expected_mode = 0o755 if info.filename.endswith(binary_name) else 0o644
                        self.assertEqual(mode, expected_mode)
            else:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
                    names = tar.getnames()
                    self.assertEqual(sorted(names), sorted(
                        [f"{root}/{binary_name}", f"{root}/LICENSE-MIT", f"{root}/THIRD_PARTY_LICENSES.md", f"{root}/BUILD-INFO.json", f"{root}/INSTALL.md"]
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
        self.assertEqual(len(prov["archives"]), 3)
        dumped = json.dumps(prov)
        self.assertNotIn('"publication_authorized": true', dumped)
        self.assertNotIn(str(self.root.resolve()), dumped)
        self.assertNotIn(str(self.out.resolve()), dumped)
        self.assertNotIn("--macos-binary", dumped)
        self.assertNotIn("--linux-binary", dumped)
        self.assertNotIn("--windows-binary", dumped)

    def test_install_safety_no_sudo_no_xattr(self) -> None:
        import zipfile
        result = self.run_builder()
        for e in result["archives"]:
            if e["filename"].endswith(".zip"):
                with zipfile.ZipFile(self.out / e["filename"], mode="r") as zf:
                    root = WINDOWS_ROOT
                    install = zf.read(f"{root}/INSTALL.md").decode("utf-8")
            else:
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
            elif "linux" in e["filename"]:
                # Linux platform notes instead of macOS signing notes.
                self.assertIn("glibc", lowered)
                self.assertIn("secret service", lowered)
                # Linux must not claim Apple signing.
                self.assertNotIn("ad-hoc", lowered)
                self.assertNotIn("developer id", lowered)
                self.assertNotIn("notarized", lowered)
            else:
                # Windows platform notes: elevation prohibited, Credential Manager, no sudo.
                self.assertIn("windows", lowered)
                self.assertIn("never require elevation", lowered)
                self.assertNotIn("ad-hoc", lowered)
                self.assertNotIn("glibc", lowered)
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
            # User-owned path, never sudo/elevation.
            if e["filename"].endswith(".zip"):
                self.assertIn("$env:USERPROFILE", install)
                self.assertIn("never require elevation", lowered)
            else:
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
        import zipfile
        with tarfile.open(self.out / MACOS_ARCHIVE, mode="r") as tar:
            mac_install = tar.extractfile(f"{MACOS_ROOT}/INSTALL.md").read().decode("utf-8")
        with tarfile.open(self.out / LINUX_ARCHIVE, mode="r") as tar:
            lin_install = tar.extractfile(f"{LINUX_ROOT}/INSTALL.md").read().decode("utf-8")
        with zipfile.ZipFile(self.out / WINDOWS_ARCHIVE, mode="r") as zf:
            win_install = zf.read(f"{WINDOWS_ROOT}/INSTALL.md").decode("utf-8")
        self.assertIn(f'grep -F "  {MACOS_ARCHIVE}" SHA256SUMS | shasum -a 256 -c -', mac_install)
        self.assertIn(f'grep -F "  {LINUX_ARCHIVE}" SHA256SUMS | sha256sum -c -', lin_install)
        self.assertIn("Get-FileHash", win_install)
        self.assertIn("SHA256 mismatch", win_install)
        self.assertIn("checksum row missing", win_install)
        self.assertNotIn("shasum -a 256 -c SHA256SUMS", mac_install)
        self.assertNotIn("sha256sum -c SHA256SUMS", lin_install)

    def test_build_info_record(self) -> None:
        import zipfile
        result = self.run_builder()
        for e in result["archives"]:
            if e["filename"].endswith(".zip"):
                root = WINDOWS_ROOT
                with zipfile.ZipFile(self.out / e["filename"], mode="r") as zf:
                    info = json.loads(zf.read(f"{root}/BUILD-INFO.json").decode("utf-8"))
            else:
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
            self.assertEqual(info["build"]["rustc_version"], LEGIT_RUSTC_LINE)
            self.assertEqual(info["build"]["cargo_version"], LEGIT_CARGO_LINE)
            self.assertEqual(info["build"]["pinned_toolchain"], "1.94.1")
            self.assertEqual(
                info["build"]["toolchain_observation"],
                "exact version lines observed in the CI build jobs and asserted again by this offline packager against the pinned 1.94.1 lines; the packager did not independently execute rustc or cargo",
            )
            self.assertNotIn("independently observed", info["build"]["toolchain_observation"])
            self.assertNotIn("independently re-observe", info["build"]["toolchain_observation"])
            self.assertIn("observed in the CI build jobs", info["build"]["toolchain_observation"])
            self.assertIn("asserted again by this offline packager", info["build"]["toolchain_observation"])
            self.assertIn("did not independently execute rustc", info["build"]["toolchain_observation"])
            for key, expected in (
                ("rustc", LEGIT_RUSTC_LINE),
                ("cargo", LEGIT_CARGO_LINE),
                ("rustc_version", LEGIT_RUSTC_LINE),
                ("cargo_version", LEGIT_CARGO_LINE),
            ):
                self.assertEqual(info["toolchain"][key], expected)
            for key in ("pinned", "pinned_toolchain"):
                self.assertEqual(info["toolchain"][key], "1.94.1")

    def test_toolchain_exact_success(self) -> None:
        result = self.run_builder(rustc_version=LEGIT_RUSTC_LINE, cargo_version=LEGIT_CARGO_LINE)
        self.assertEqual(result["tag"], TAG)
        prov = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(prov["toolchain"]["rustc"], LEGIT_RUSTC_LINE)
        self.assertEqual(prov["toolchain"]["cargo"], LEGIT_CARGO_LINE)

    def test_mutated_regeneration_script_rejected(self) -> None:
        script = self.root / "support" / "update-evm-test-fixtures.py"
        script.write_text(script.read_text(encoding="utf-8") + "\n# tamper\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-q", "-m", "tamper script"], check=True)
        subprocess.run(["git", "-C", str(self.root), "tag", "-f", TAG], check=True)
        with self.assertRaisesRegex(BUILDER.ReleaseError, "regeneration script SHA-256 changed"):
            self.run_builder()

    def _rewrite_provenance(self, mutate) -> None:
        path = self.root / "tests/fixtures/PROVENANCE.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        mutate(data)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-q", "-m", "provenance change"], check=True)
        subprocess.run(["git", "-C", str(self.root), "tag", "-f", TAG], check=True)

    def test_gate_status_downgrade_rejected(self) -> None:
        def mutate(data):
            for entry in data["fixtures"]:
                if entry["id"] == "FIX-02":
                    entry["regeneration"] = {
                        "status": "not_scripted",
                        "performed_in_this_review": False,
                        "detail": "data-only downgrade",
                    }
                    return
            self.fail("FIX-02 fixture missing")

        self._rewrite_provenance(mutate)
        with self.assertRaisesRegex(BUILDER.ReleaseError, "regeneration status must be scripted"):
            self.run_builder()

    def test_gate_script_swap_rejected(self) -> None:
        def mutate(data):
            for entry in data["fixtures"]:
                if entry["id"] == "FIX-02":
                    entry["regeneration"]["script"] = "support/update-evm-test-fixtures.py"
                    entry["regeneration"]["script_sha256"] = (
                        "8d96c7ee80c021de9d3f679c17322db4da1fa7433c23429fde9eef1407b18615"
                    )
                    return
            self.fail("FIX-02 fixture missing")

        self._rewrite_provenance(mutate)
        with self.assertRaisesRegex(BUILDER.ReleaseError, "regeneration script changed"):
            self.run_builder()

    def test_windows_non_pe_binary_rejected(self) -> None:
        with tempfile.NamedTemporaryFile(prefix="not-a-pe-", delete=False) as handle:
            handle.write(FAKE_ELF)
            not_pe = Path(handle.name)
        try:
            with self.assertRaisesRegex(BUILDER.ReleaseError, "not a PE"):
                self.run_builder(windows_binary=not_pe)
        finally:
            not_pe.unlink()

    def test_windows_truncated_binary_rejected(self) -> None:
        with tempfile.NamedTemporaryFile(prefix="truncated-pe-", delete=False) as handle:
            handle.write(b"MZ" + bytes(10))
            truncated = Path(handle.name)
        try:
            with self.assertRaisesRegex(BUILDER.ReleaseError, "too small"):
                self.run_builder(windows_binary=truncated)
        finally:
            truncated.unlink()

    def test_windows_wrong_arch_rejected(self) -> None:
        other = bytearray(FAKE_PE)
        other[0x3C:0x40] = (64).to_bytes(4, "little")
        other[64:68] = b"PE\x00\x00"
        other[64 + 4:64 + 6] = (0x014C).to_bytes(2, "little")
        with tempfile.NamedTemporaryFile(prefix="wrong-arch-pe-", delete=False) as handle:
            handle.write(bytes(other))
            wrong_arch = Path(handle.name)
        try:
            with self.assertRaisesRegex(BUILDER.ReleaseError, "not an x86-64"):
                self.run_builder(windows_binary=wrong_arch)
        finally:
            wrong_arch.unlink()

    def test_mismatched_rustc_rejected(self) -> None:
        with self.assertRaisesRegex(BUILDER.ReleaseError, "--rustc-version"):
            self.run_builder(rustc_version="rustc 1.95.0 (e408947bf 2026-03-25)")
        self.assertFalse(self.out.exists())

    def test_mismatched_cargo_rejected(self) -> None:
        with self.assertRaisesRegex(BUILDER.ReleaseError, "--cargo-version"):
            self.run_builder(cargo_version="cargo 1.95.0 (29ea6fb6a 2026-03-24)")
        self.assertFalse(self.out.exists())

    def test_missing_toolchain_args_rejected(self) -> None:
        with self.assertRaises(TypeError):
            BUILDER.run(
                source_root=self.root,
                output_dir=self.out,
                tag=TAG,
                repository_id="123456789",
                macos_binary=self.macos_bin,
                linux_binary=self.linux_bin,
            )
        with self.assertRaises(BUILDER.ReleaseError):
            BUILDER.run(
                source_root=self.root,
                output_dir=self.out,
                tag=TAG,
                repository_id="123456789",
                macos_binary=self.macos_bin,
                linux_binary=self.linux_bin,
                windows_binary=self.windows_bin,
                rustc_version=LEGIT_RUSTC_LINE,
            )
        with self.assertRaises(BUILDER.ReleaseError):
            BUILDER.run(
                source_root=self.root,
                output_dir=self.root / "should-not-exist",
                tag=TAG,
                repository_id="123456789",
                macos_binary=self.macos_bin,
                linux_binary=self.linux_bin,
                windows_binary=self.windows_bin,
                rustc_version=LEGIT_RUSTC_LINE,
                cargo_version="",
            )
        with self.assertRaises(SystemExit) as context:
            BUILDER.main(
                [
                    "--tag", TAG,
                    "--repository-id", "123456789",
                    "--macos-binary", str(self.macos_bin),
                    "--linux-binary", str(self.linux_bin),
                    "--windows-binary", str(self.windows_bin),
                    "--source-root", str(self.root),
                    "--output-dir", str(self.out),
                ]
            )
        self.assertEqual(context.exception.code, 2)
        self.assertFalse(self.out.exists())

    def test_provenance_toolchain_fields(self) -> None:
        self.run_builder()
        prov = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        toolchain = prov["toolchain"]
        self.assertEqual(toolchain["rustc"], LEGIT_RUSTC_LINE)
        self.assertEqual(toolchain["cargo"], LEGIT_CARGO_LINE)
        self.assertEqual(toolchain["rustc_version"], LEGIT_RUSTC_LINE)
        self.assertEqual(toolchain["cargo_version"], LEGIT_CARGO_LINE)
        for key in ("pinned", "pinned_toolchain"):
            self.assertEqual(toolchain[key], "1.94.1")

    def test_no_unsupported_independently_observed_claim(self) -> None:
        self.run_builder()
        prov_text = (self.out / "release-provenance.json").read_text(encoding="utf-8")
        self.assertNotIn("independently observed", prov_text)
        self.assertNotIn("independently re-observe", prov_text)
        import zipfile
        for e in json.loads(prov_text)["archives"]:
            if e["filename"].endswith(".zip"):
                root = WINDOWS_ROOT
                with zipfile.ZipFile(self.out / e["filename"], mode="r") as zf:
                    info_text = zf.read(f"{root}/BUILD-INFO.json").decode("utf-8")
            else:
                root = MACOS_ROOT if "macos" in e["filename"] else LINUX_ROOT
                with tarfile.open(self.out / e["filename"], mode="r") as tar:
                    info_text = tar.extractfile(f"{root}/BUILD-INFO.json").read().decode("utf-8")
            self.assertNotIn("independently observed", info_text)
            self.assertNotIn("independently re-observe", info_text)
            self.assertIn("did not independently execute rustc", info_text)

    def test_draft_only_release_controls(self) -> None:
        result = self.run_builder()
        prov = json.loads((self.out / "release-provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(
            prov["gate"]["release_controls"],
            "DRAFT-ONLY \u2014 OWNER SELF-APPROVAL AFTER IMMUTABLE TAG/RELEASE VERIFICATION",
        )
        self.assertFalse(prov["owner_self_approval"]["independent_reviewer"])
        self.assertTrue(prov["owner_self_approval"]["residual_risk_accepted"])
        self.assertEqual(prov["historical_release_intent"]["tag"], "v0.1.0-testnet.1")
        import zipfile
        for e in result["archives"]:
            if e["filename"].endswith(".zip"):
                root = WINDOWS_ROOT
                with zipfile.ZipFile(self.out / e["filename"], mode="r") as zf:
                    info = json.loads(zf.read(f"{root}/BUILD-INFO.json").decode("utf-8"))
            else:
                root = MACOS_ROOT if "macos" in e["filename"] else LINUX_ROOT
                with tarfile.open(self.out / e["filename"], mode="r") as tar:
                    info = json.loads(tar.extractfile(f"{root}/BUILD-INFO.json").read().decode("utf-8"))
            self.assertEqual(info["release_controls"]["publication_mode"], "draft-only-manual-publish")
            self.assertTrue(info["release_controls"]["manual_publish_required"])
            self.assertTrue(info["release_controls"]["immutable_setting_admin_verification_required"])
            self.assertTrue(info["release_controls"]["immutable_release"])
            self.assertTrue(info["release_controls"]["owner_self_approval"])
            self.assertFalse(info["release_controls"]["environment_prevent_self_review"])
            self.assertFalse(info["release_controls"]["independent_environment_review"])
            self.assertEqual(info["release_controls"]["environment_reviewer_owner_id"], 86115037)
            self.assertEqual(info["release_controls"]["tag_policy"], "refs/tags/v0.1.0-testnet.4")
            self.assertEqual(
                info["release_controls"]["tag_ruleset_exact_scope"],
                "refs/tags/v*",
            )
            self.assertTrue(info["release_controls"]["tag_creation_rule_required"])
            self.assertEqual(
                info["release_controls"]["tag_creation_ruleset_name"],
                "astatine-release-tag-creation",
            )
            self.assertEqual(
                info["release_controls"]["tag_creation_bypass_actors_allowed"],
                [
                    {
                        "actor_id": 86115037,
                        "actor_type": "User",
                        "bypass_mode": "always",
                    },
                ],
            )
            self.assertEqual(
                info["release_controls"]["tag_immutability_ruleset_name"],
                "astatine-release-tags",
            )
            self.assertEqual(
                info["release_controls"]["tag_immutability_scope"],
                ["refs/tags/v*"],
            )
            self.assertEqual(
                info["release_controls"]["tag_immutability_bypass_actors_allowed"], 0
            )

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
            "release tag and draft assets are rechecked immediately before manual publication",
            blockers,
        )
        self.assertIn(
            "owner self-approval reduces separation of duties; no independent review is claimed",
            blockers,
        )
        self.assertIn(
            "separate active astatine-release-tag-creation ruleset restricted to exactly refs/tags/v* with no exclusions and with exactly the owner-user (User 86115037, always) creation bypass; repository-admin bypass is rejected",
            blockers,
        )
        self.assertIn(
            "separate active astatine-release-tags ruleset limited to update, deletion and non-fast-forward for exactly refs/tags/v* with no exclusions and with zero bypass actors",
            blockers,
        )
        self.assertIn(
            "tag creation protection is retained; no broader bypass or removal of the creation rule is authorized",
            blockers,
        )

    def test_wrong_tag_rejected(self) -> None:
        with self.assertRaises(BUILDER.ReleaseError):
            self.run_builder(tag="v0.1.0-testnet.2")

    def test_tag_version_mismatch_rejected(self) -> None:
        (self.root / "Cargo.toml").write_text(
            (self.root / "Cargo.toml").read_text().replace("0.1.0-testnet.4", "0.1.0-testnet.9"),
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
