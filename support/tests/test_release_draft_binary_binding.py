#!/usr/bin/env python3
"""Regression tests for the release-draft packaged-binary binding step.

These tests extract the actual inline Python validator from
``.github/workflows/release.yml`` and run it against synthetic release bundles.
They verify that the draft refuses archive/layout tampering and binds the
packaged binary to the provenance record before the shell step verifies the
extracted binary with ``gh attestation verify``. They never touch the real
repository, network, GitHub, wallets, or release state.
"""

from __future__ import annotations

import hashlib
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
STEP_NAME = "Verify packaged binaries match attested compiled binaries"
TAG = "v0.1.0-testnet.6"
COMMIT = "0123456789abcdef0123456789abcdef01234567"

MACOS_BINARY = (
    b"\xcf\xfa\xed\xfe"
    + (0x0100000C).to_bytes(4, "little")
    + b"\x00" * 4
    + (2).to_bytes(4, "little")
    + b"\x00" * 16
)
LINUX_BINARY = bytearray(64)
LINUX_BINARY[0:4] = b"\x7fELF"
LINUX_BINARY[4] = 2
LINUX_BINARY[5] = 1
LINUX_BINARY[18:20] = (62).to_bytes(2, "little")
LINUX_BINARY = bytes(LINUX_BINARY)
WINDOWS_BINARY = (
    b"MZ" + bytes(58) + (64).to_bytes(4, "little")
    + b"PE\x00\x00" + (0x8664).to_bytes(2, "little") + bytes(20) + bytes(64)
)

TARGETS = {
    "astatine-v0.1.0-testnet.6-macos-arm64.tar.gz": (
        "astatine-v0.1.0-testnet.6-macos-arm64",
        "aarch64-apple-darwin",
        MACOS_BINARY,
        "astatine",
        False,
    ),
    "astatine-v0.1.0-testnet.6-linux-x86_64.tar.gz": (
        "astatine-v0.1.0-testnet.6-linux-x86_64",
        "x86_64-unknown-linux-gnu",
        LINUX_BINARY,
        "astatine",
        False,
    ),
    "astatine-v0.1.0-testnet.6-windows-x86_64.zip": (
        "astatine-v0.1.0-testnet.6-windows-x86_64",
        "x86_64-pc-windows-msvc",
        WINDOWS_BINARY,
        "astatine.exe",
        True,
    ),
}
FILES = (
    ("astatine", 0o755),
    ("BUILD-INFO.json", 0o644),
    ("INSTALL.md", 0o644),
    ("LICENSE-MIT", 0o644),
    ("THIRD_PARTY_LICENSES.md", 0o644),
)
FILES_WINDOWS = (
    ("astatine.exe", 0o755),
    ("BUILD-INFO.json", 0o644),
    ("INSTALL.md", 0o644),
    ("LICENSE-MIT", 0o644),
    ("THIRD_PARTY_LICENSES.md", 0o644),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_script() -> str:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["release-draft"]["steps"]
    run = next(step["run"] for step in steps if step.get("name") == STEP_NAME)
    marker = "<<'PY'\n"
    assert marker in run, "draft binding step must contain an inline Python heredoc"
    return run.split(marker, 1)[1].rsplit("\nPY\n", 1)[0]


class DraftBinaryBindingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="draft-binding-"))
        self.script = load_script()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_bundle(
        self,
        *,
        tamper_binary: bool = False,
        cross_target: bool = False,
        bad_format: bool = False,
        symlink_binary: bool = False,
        wrong_mode: bool = False,
        extra_member: bool = False,
        traversal_member: bool = False,
        duplicate_member: bool = False,
        missing_binary_sha: bool = False,
        corrupt_archive_hash: bool = False,
    ) -> tuple[pathlib.Path, pathlib.Path]:
        bundle = self.tmp / "bundle"
        bundle.mkdir()
        out = self.tmp / "out"
        entries = []
        sums = []
        for filename, (root, target, binary, binary_name, is_zip) in TARGETS.items():
            stored_binary = binary
            if tamper_binary:
                stored_binary = b"TAMPERED-BINARY"
            if bad_format:
                stored_binary = b"NOT-A-BINARY"
            if cross_target and target == "x86_64-unknown-linux-gnu":
                stored_binary = MACOS_BINARY
            if cross_target and target == "x86_64-pc-windows-msvc":
                stored_binary = LINUX_BINARY
            provenance_binary = binary if tamper_binary else stored_binary
            files = FILES_WINDOWS if is_zip else FILES
            file_data = {
                binary_name: stored_binary,
                "BUILD-INFO.json": b"{}",
                "INSTALL.md": b"install",
                "LICENSE-MIT": b"mit",
                "THIRD_PARTY_LICENSES.md": b"third-party",
            }
            archive_path = bundle / filename
            if is_zip:
                import zipfile
                with zipfile.ZipFile(archive_path, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
                    for name, mode in files:
                        data = file_data[name]
                        info = zipfile.ZipInfo(filename=f"{root}/{name}")
                        info.date_time = (1980, 1, 1, 0, 0, 0)
                        info.compress_type = zipfile.ZIP_DEFLATED
                        info.create_system = 3
                        eff_mode = 0o777 if wrong_mode and name == binary_name else mode
                        info.external_attr = (eff_mode & 0xFFFF) << 16
                        # Symlink simulation for zip: create a directory entry with same name to force failure
                        if symlink_binary and name == binary_name:
                            # Write a directory entry instead to trigger regular-file failure
                            dir_info = zipfile.ZipInfo(filename=f"{root}/{name}/")
                            dir_info.date_time = (1980, 1, 1, 0, 0, 0)
                            dir_info.external_attr = (0o755 << 16) | 0x10
                            zf.writestr(dir_info, b"")
                            continue
                        zf.writestr(info, data)
                    if extra_member:
                        zf.writestr(f"{root}/EXTRA", b"extra")
                    if traversal_member:
                        zf.writestr(f"{root}/../evil", b"traversal")
                    if duplicate_member:
                        # zipfile allows duplicates; write twice to trigger duplicate detection
                        info = zipfile.ZipInfo(filename=f"{root}/{binary_name}")
                        info.date_time = (1980, 1, 1, 0, 0, 0)
                        info.external_attr = (0o755 << 16)
                        zf.writestr(info, file_data[binary_name])
            else:
                with tarfile.open(archive_path, mode="w:gz") as tar:
                    for name, mode in files:
                        data = file_data[name]
                        info = tarfile.TarInfo(f"{root}/{name}")
                        if name == binary_name and symlink_binary:
                            info.type = tarfile.SYMTYPE
                            info.linkname = "attested-binary"
                            info.size = 0
                            tar.addfile(info)
                            continue
                        info.size = len(data)
                        info.mode = 0o777 if wrong_mode and name == binary_name else mode
                        info.type = tarfile.REGTYPE
                        tar.addfile(info, io.BytesIO(data))
                    if extra_member:
                        data = b"extra"
                        info = tarfile.TarInfo(f"{root}/EXTRA")
                        info.size = len(data)
                        info.mode = 0o644
                        info.type = tarfile.REGTYPE
                        tar.addfile(info, io.BytesIO(data))
                    if traversal_member:
                        data = b"traversal"
                        info = tarfile.TarInfo(f"{root}/../evil")
                        info.size = len(data)
                        info.mode = 0o644
                        info.type = tarfile.REGTYPE
                        tar.addfile(info, io.BytesIO(data))
                    if duplicate_member:
                        data = file_data[binary_name]
                        info = tarfile.TarInfo(f"{root}/{binary_name}")
                        info.size = len(data)
                        info.mode = 0o755
                        info.type = tarfile.REGTYPE
                        tar.addfile(info, io.BytesIO(data))

            members = []
            for name, mode in files:
                data = file_data[name]
                members.append(
                    {
                        "archive_path": f"{root}/{name}",
                        "sha256": sha256(data),
                        "bytes": len(data),
                        "mode": oct(0o777 if wrong_mode and name == binary_name else mode),
                    }
                )
            entry = {
                "target": target,
                "filename": filename,
                "sha256": sha256(archive_path.read_bytes()),
                "bytes": archive_path.stat().st_size,
                "members": members,
                "binary_sha256": sha256(provenance_binary),
                "binary_bytes": len(provenance_binary),
            }
            if missing_binary_sha:
                del entry["binary_sha256"]
            entries.append(entry)
            sums.append(f"{sha256(archive_path.read_bytes())}  {filename}\n")

        (bundle / "SHA256SUMS").write_text("".join(sums), encoding="utf-8")
        (bundle / "release-provenance.json").write_text(
            json.dumps({"tag": TAG, "commit": COMMIT, "archives": entries}),
            encoding="utf-8",
        )
        if corrupt_archive_hash:
            archive = bundle / next(iter(TARGETS))
            archive.write_bytes(archive.read_bytes() + b"tamper")
        return bundle, out

    def run_validator(self, bundle: pathlib.Path, out: pathlib.Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-", str(bundle), str(out), COMMIT, TAG],
            input=self.script,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_valid_bundle_passes_and_manifest_is_written(self) -> None:
        bundle, out = self.make_bundle()
        result = self.run_validator(bundle, out)
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(set(manifest["binaries"]), {v[1] for v in TARGETS.values()})
        for target, record in manifest["binaries"].items():
            expected_binary = next(v[2] for v in TARGETS.values() if v[1] == target)
            self.assertEqual(record["sha256"], sha256(expected_binary))
            dest = "astatine.exe" if target == "x86_64-pc-windows-msvc" else "astatine"
            self.assertTrue((out / target / dest).is_file())

    def test_tampered_binary_member_fails(self) -> None:
        bundle, out = self.make_bundle(tamper_binary=True)
        result = self.run_validator(bundle, out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("packaged binary sha256 does not match provenance", result.stderr)

    def test_cross_target_binary_fails(self) -> None:
        bundle, out = self.make_bundle(cross_target=True)
        result = self.run_validator(bundle, out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Linux binary format mismatch", result.stderr)

    def test_invalid_binary_format_fails(self) -> None:
        bundle, out = self.make_bundle(bad_format=True)
        result = self.run_validator(bundle, out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("binary format mismatch", result.stderr)

    def test_symlink_binary_member_fails(self) -> None:
        bundle, out = self.make_bundle(symlink_binary=True)
        result = self.run_validator(bundle, out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive member must be a regular file", result.stderr)

    def test_wrong_binary_mode_fails(self) -> None:
        bundle, out = self.make_bundle(wrong_mode=True)
        result = self.run_validator(bundle, out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive member mode mismatch", result.stderr)

    def test_extra_member_fails(self) -> None:
        bundle, out = self.make_bundle(extra_member=True)
        result = self.run_validator(bundle, out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive member is outside the allowlist", result.stderr)

    def test_traversal_member_fails(self) -> None:
        bundle, out = self.make_bundle(traversal_member=True)
        result = self.run_validator(bundle, out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive member path is unsafe", result.stderr)

    def test_duplicate_member_fails(self) -> None:
        bundle, out = self.make_bundle(duplicate_member=True)
        result = self.run_validator(bundle, out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate archive member", result.stderr)

    def test_missing_binary_sha_fails(self) -> None:
        bundle, out = self.make_bundle(missing_binary_sha=True)
        result = self.run_validator(bundle, out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("packaged binary sha256 does not match provenance", result.stderr)

    def test_archive_hash_tamper_fails(self) -> None:
        bundle, out = self.make_bundle(corrupt_archive_hash=True)
        result = self.run_validator(bundle, out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive sha256 does not match SHA256SUMS", result.stderr)


if __name__ == "__main__":
    unittest.main()
