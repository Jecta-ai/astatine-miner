#!/usr/bin/env python3
"""Regression tests for the Windows archive validation path (v0.1.0-testnet.6).

Single source of truth is the inline ``Extract Windows archive to sandbox``
``run: |`` block in ``.github/workflows/release.yml``. Pre-tag CI on a native
Windows runner extracts that block verbatim via
``support/release/extract-windows-smoke.py`` and executes it against
realistic deterministic synthetic ZIPs, so the release acceptance code and
the tested code are byte-identical.

Catches the v0.1.0-testnet.5 failure where
``$root = "astatine-$env:RELEASE_TAG-windows-x86_64/"`` combined with
``"$root/astatine.exe"`` produced double-slash expectations that never
matched the real archive.

Run with ``python3 -B`` only. No network, no binary execution.
"""

from __future__ import annotations

import importlib.util
import io
import pathlib
import re
import unittest
import zipfile

SOURCE_ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW_PATH = SOURCE_ROOT / ".github" / "workflows" / "release.yml"
CI_PATH = SOURCE_ROOT / ".github" / "workflows" / "ci.yml"
EXTRACTOR_PATH = SOURCE_ROOT / "support" / "release" / "extract-windows-smoke.py"

TAG = "v0.1.0-testnet.6"
ROOT = f"astatine-{TAG}-windows-x86_64"
EXPECTED = sorted(
    [
        f"{ROOT}/astatine.exe",
        f"{ROOT}/LICENSE-MIT",
        f"{ROOT}/THIRD_PARTY_LICENSES.md",
        f"{ROOT}/BUILD-INFO.json",
        f"{ROOT}/INSTALL.md",
    ]
)


def load_extractor():
    spec = importlib.util.spec_from_file_location("extract_windows_smoke", EXTRACTOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load extractor module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_zip(members: dict[str, bytes]) -> bytes:
    items = sorted(members.items())
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for name, data in items:
            info = zipfile.ZipInfo(filename=name)
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            mode = 0o755 if name.endswith("astatine.exe") else 0o644
            info.external_attr = (mode & 0xFFFF) << 16
            zf.writestr(info, data)
    return buffer.getvalue()


def base_members() -> dict[str, bytes]:
    return {
        f"{ROOT}/astatine.exe": b"fake-pe-binary-for-validation-only",
        f"{ROOT}/LICENSE-MIT": b"MIT license placeholder\n",
        f"{ROOT}/THIRD_PARTY_LICENSES.md": b"# Third party notices placeholder\n",
        f"{ROOT}/BUILD-INFO.json": b'{"synthetic": true}\n',
        f"{ROOT}/INSTALL.md": b"# Install placeholder\n",
    }


def validate_names(names: list[str]) -> None:
    for name in EXPECTED:
        if "//" in name:
            raise AssertionError(f"invalid expected member (double slash): {name}")
    for name in names:
        if "\\" in name:
            raise AssertionError(f"unsafe archive member (backslash): {name}")
        if name.startswith("/"):
            raise AssertionError(f"unsafe archive member (absolute): {name}")
        if re.search(r"(^|/)\.\.(/|$)", name):
            raise AssertionError(f"unsafe archive member (traversal): {name}")
    for name in EXPECTED:
        if name not in names:
            raise AssertionError(f"archive member missing: {name}")
    for name in names:
        if name not in EXPECTED:
            raise AssertionError(f"unexpected archive member: {name}")


def zip_names(data: bytes) -> list[str]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return [info.filename for info in zf.infolist()]


class WindowsArchiveValidationTest(unittest.TestCase):
    def test_positive_synthetic_zip_passes(self) -> None:
        validate_names(zip_names(build_zip(base_members())))

    def test_missing_member_fails(self) -> None:
        members = {k: v for k, v in base_members().items() if not k.endswith("INSTALL.md")}
        with self.assertRaisesRegex(AssertionError, "archive member missing"):
            validate_names(zip_names(build_zip(members)))

    def test_extra_member_fails(self) -> None:
        members = dict(base_members())
        members[f"{ROOT}/evil.exe"] = b"unexpected"
        with self.assertRaisesRegex(AssertionError, "unexpected archive member"):
            validate_names(zip_names(build_zip(members)))

    def test_double_slash_member_fails(self) -> None:
        members: dict[str, bytes] = {}
        for key, value in base_members().items():
            if key.endswith("astatine.exe"):
                members[key.replace(f"{ROOT}/", f"{ROOT}//", 1)] = value
            else:
                members[key] = value
        with self.assertRaises(AssertionError):
            validate_names(zip_names(build_zip(members)))

    def test_backslash_member_fails(self) -> None:
        members = dict(base_members())
        members[f"{ROOT}\\evil.exe"] = b"unexpected"
        with self.assertRaisesRegex(AssertionError, "backslash"):
            validate_names(zip_names(build_zip(members)))

    def test_traversal_member_fails(self) -> None:
        members = dict(base_members())
        members[f"{ROOT}/../evil.exe"] = b"unexpected"
        with self.assertRaisesRegex(AssertionError, "traversal"):
            validate_names(zip_names(build_zip(members)))

    def test_absolute_member_fails(self) -> None:
        members = dict(base_members())
        members["/absolute-evil.exe"] = b"unexpected"
        with self.assertRaisesRegex(AssertionError, "absolute"):
            validate_names(zip_names(build_zip(members)))

    def test_extracted_block_is_verbatim_release_code(self) -> None:
        extractor = load_extractor()
        workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
        block = extractor.extract_run_block(workflow_text)
        # Fixed root without trailing slash; no double-slash expectation.
        self.assertIn('$root = "astatine-$env:RELEASE_TAG-windows-x86_64"', block)
        self.assertNotIn('windows-x86_64/"', block)
        self.assertNotRegex(block, r'\$root\s*=\s*"[^"]*/"\s*$')
        # Guards and sandbox paths must match the release acceptance path.
        self.assertIn("double slash", block.lower())
        self.assertIn("backslash", block.lower())
        self.assertIn("traversal", block.lower())
        self.assertIn("Expand-Archive", block)
        self.assertIn("-LiteralPath", block)
        self.assertIn("win-archive-smoke", block)
        self.assertIn('bundle/astatine-*-windows-x86_64.zip', block)
        for member in ("astatine.exe", "LICENSE-MIT", "THIRD_PARTY_LICENSES.md", "BUILD-INFO.json", "INSTALL.md"):
            self.assertIn(f"$root/{member}", block)
        # The validation block must never execute the packaged binary.
        self.assertNotIn("& $exe", block)
        self.assertNotIn("--version", block)

    def test_release_workflow_has_no_double_slash(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        section = workflow.split("Extract Windows archive to sandbox", 1)[1].split(
            "Smoke test packaged Windows executable", 1
        )[0]
        self.assertIn('$root = "astatine-$env:RELEASE_TAG-windows-x86_64"', section)
        self.assertNotIn('windows-x86_64/"', section)
        self.assertNotIn("//astatine.exe", section)

    def test_release_smoke_exe_path_has_no_double_slash(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        smoke = workflow.split("Smoke test packaged Windows executable", 1)[1].split("release-draft:", 1)[0]
        self.assertIn("$exe", smoke)
        self.assertIn("& $exe --version", smoke)
        self.assertNotIn("//astatine.exe", smoke)
        self.assertIn("-LiteralPath", smoke)

    def test_ci_executes_verbatim_release_script(self) -> None:
        ci = CI_PATH.read_text(encoding="utf-8")
        # CI must use the verbatim extractor, not a separate PowerShell copy.
        self.assertIn("extract-windows-smoke.py", ci)
        self.assertIn("--workflow .github/workflows/release.yml", ci)
        self.assertIn("--out", ci)
        self.assertNotIn("verify-windows-archive.ps1", ci)
        # CI must use the same bundle and sandbox paths as release.
        self.assertIn("astatine-$tag-windows-x86_64.zip", ci)
        self.assertIn("'bundle'", ci)
        self.assertIn("win-archive-smoke", ci)
        self.assertIn("& $extracted", ci)
        # CI must resolve Python without assuming python3 exists on Windows bash.
        self.assertIn("Get-Command", ci)
        # CI must cover all negative classes natively with no execution.
        for case in ("neg-missing.zip", "neg-extra.zip", "neg-doubleslash.zip", "neg-backslash.zip", "neg-traversal.zip", "neg-absolute.zip"):
            self.assertIn(case, ci)
        self.assertIn("-LiteralPath", ci)
        # PowerShell .ps1 invocation must rely on terminating errors, not
        # $LASTEXITCODE (which stays $null for .ps1 and would false-fail
        # positive). Native python calls may still check $LASTEXITCODE.
        self.assertNotIn("exact release script failed on positive", ci)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
