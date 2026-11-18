#!/usr/bin/env python3
"""Offline release-intent dual-platform release packager (no publication, draft-only).

Uses support/release/gate.py and requires the owner-authorized release-intent
licensing state (not final publication authorization; final release controls
remain outstanding).
Packages exactly two deterministic archives for the exact tag
``v0.1.0-testnet.3`` — macOS ARM64 and Linux x86_64 — each with exactly
``astatine``, ``LICENSE-MIT``, ``THIRD_PARTY_LICENSES.md``, ``BUILD-INFO.json``,
and ``INSTALL.md``. Generates deterministic ``BUILD-INFO.json`` (schema
``astatine-build-info/v1``) and platform-specific ``INSTALL.md``, emits
``SHA256SUMS`` and ``release-provenance.json`` with no absolute paths or raw
invocation, and refuses fixtures, forbidden globs, symlinks, in-tree output,
pre-existing output, wrong tag/version/commit, dirty trees, wrong binary
formats, and duplicate/missing members.

This script never executes candidate code, wallets, mining, or the network;
it only reads prebuilt binaries to validate headers and archive them. Binary
identity and source linkage are NOT established by this packager: its header
check is a format check only (Low-10 limitation), and the workflow build jobs
plus GitHub build provenance are the linkage control. It performs no OIDC, attestation dispatch,
upload, tag creation, publication, or GitHub release — those external controls
(protected environment, exact tag, exact-commit main CI, attestations,
draft-only manual publication after admin immutable-setting verification) are
enforced by the release workflow preflight/build jobs and owner manual
publication, not by this offline packager. The dry-run rehearsal remains
support/release/build-dry-run.py, which never publishes even when the
licensing gate is authorized.

Low-10 limitation: this packager validates binary format only (Mach-O 64-bit
ARM64 / ELF64 x86_64 headers); it does not prove binary identity or
source-to-binary linkage. Binary identity is established by the workflow build
jobs and GitHub build provenance, not by this offline packager.

Usage:
    python3 -B support/release/build-release.py --tag v0.1.0-testnet.3 \\
        --repository-id <digits> --macos-binary <path> --linux-binary <path> \\
        --rustc-version "rustc 1.94.1 (e408947bf 2026-03-25)" \\
        --cargo-version "cargo 1.94.1 (29ea6fb6a 2026-03-24)" \\
        --output-dir <new-or-empty-dir-outside-source>
"""

from __future__ import annotations

import argparse
import datetime
import fnmatch
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

PROVENANCE_REL = "tests/fixtures/PROVENANCE.json"
INVENTORY_REL = "support/release/distribution-inventory.json"
CARGO_TOML_REL = "Cargo.toml"
CARGO_LOCK_REL = "Cargo.lock"
REPOSITORY_REL = "support/release-repository.txt"
LICENSE_MIT_REL = "LICENSE-MIT"
THIRD_PARTY_REL = "THIRD_PARTY_LICENSES.md"

EXPECTED_REPOSITORY = "Jecta-ai/astatine-miner"
EXPECTED_PACKAGE_NAME = "astatine-cli-rust"
EXPECTED_BINARY_NAME = "astatine"
EXPECTED_PROFILE = "release"
EXPECTED_CARGO_COMMAND = "cargo build --locked --release"
EXPECTED_RUSTC_VERSION_LINE = "rustc 1.94.1 (e408947bf 2026-03-25)"
EXPECTED_CARGO_VERSION_LINE = "cargo 1.94.1 (29ea6fb6a 2026-03-24)"
EXPECTED_TOOLCHAIN = "1.94.1"
BUILD_INFO_SCHEMA = "astatine-build-info/v1"
FILE_MODE_DOC = 0o644
FILE_MODE_BIN = 0o755
DETERMINISTIC_MTIME = 0
OUTPUT_FILE_MODE = 0o600
BINARY_BUILD_LINKAGE_NOTE = (
    "workflow-built from the exact release tag; build-provenance attestation is "
    "required to link each archived binary to that tag build, and independent "
    "bit-for-bit reproducibility across hosts is not claimed by this package"
)
EXPECTED_RELEASE_VERSION = "0.1.0-testnet.3"
RELEASE_NOTES_TAG = "v0.1.0-testnet.3"
MACOS_TARGET = "aarch64-apple-darwin"
LINUX_TARGET = "x86_64-unknown-linux-gnu"
MACOS_ARCHIVE = "astatine-v0.1.0-testnet.3-macos-arm64.tar.gz"
LINUX_ARCHIVE = "astatine-v0.1.0-testnet.3-linux-x86_64.tar.gz"
MACOS_ROOT = "astatine-v0.1.0-testnet.3-macos-arm64"
LINUX_ROOT = "astatine-v0.1.0-testnet.3-linux-x86_64"
EXPECTED_BASENAMES = ["BUILD-INFO.json", "INSTALL.md", "LICENSE-MIT", "THIRD_PARTY_LICENSES.md", "astatine"]


class ReleaseError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def require_object(value: object, label: str) -> dict:
    require(isinstance(value, dict), f"{label} must be an object")
    return value  # type: ignore[return-value]


def require_string(value: object, label: str) -> str:
    require(isinstance(value, str) and value, f"{label} must be a non-empty string")
    return value  # type: ignore[return-value]


def validate_relative_path(value: object, label: str) -> str:
    require(isinstance(value, str) and value, f"{label} must be a non-empty relative path string")
    require("\x00" not in value, f"{label} must not contain NUL")  # type: ignore[operator]
    require("\\" not in value, f"{label} must not contain backslash: {value}")  # type: ignore[operator]
    path = PurePosixPath(value)  # type: ignore[arg-type]
    require(not path.is_absolute(), f"{label} must not be absolute: {value}")
    parts = path.parts
    require(parts and all(part not in ("", ".", "..") for part in parts), f"{label} contains traversal: {value}")
    require(path.as_posix() == value, f"{label} is not a canonical relative path: {value}")
    return value  # type: ignore[return-value]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_gate_module():  # type: ignore[no-untyped-def]
    gate_path = Path(__file__).resolve().parent / "gate.py"
    spec = importlib.util.spec_from_file_location("astatine_release_gate", gate_path)
    if spec is None or spec.loader is None:
        raise ReleaseError("cannot load release gate module")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    except Exception as error:
        raise ReleaseError("cannot load release gate module") from error
    return module


def read_confined_bytes(root: Path, relative: str, label: str) -> bytes:
    validate_relative_path(relative, f"{label} path")
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        try:
            status = current.lstat()
        except OSError as error:
            raise ReleaseError(f"cannot read {label} {relative}") from error
        require(not stat.S_ISLNK(status.st_mode), f"{label} path contains a symlink component: {relative}")
    require(stat.S_ISREG(status.st_mode), f"{label} must be a regular file: {relative}")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise ReleaseError(f"{label} escapes the source root: {relative}") from error
    try:
        return current.read_bytes()
    except OSError as error:
        raise ReleaseError(f"cannot read {label} {relative}") from error


def read_input_binary(path: Path, label: str) -> bytes:
    # Input binaries may live outside the source tree; validate without
    # executing and without recording absolute paths.
    try:
        status = path.lstat()
    except OSError as error:
        raise ReleaseError(f"cannot read {label} binary") from error
    require(not stat.S_ISLNK(status.st_mode), f"{label} binary must not be a symlink")
    require(stat.S_ISREG(status.st_mode), f"{label} binary must be a regular file")
    try:
        return path.read_bytes()
    except OSError as error:
        raise ReleaseError(f"cannot read {label} binary") from error


def require_macho_arm64(data: bytes, label: str) -> None:
    require(len(data) >= 32, f"{label} binary is too small to be a Mach-O executable")
    require(data[0:4] == b"\xcf\xfa\xed\xfe", f"{label} binary is not a 64-bit Mach-O object")
    require(int.from_bytes(data[4:8], "little") == 0x0100000C, f"{label} binary is not an ARM64 (cputype) Mach-O object")
    # Filetype at offset 12 should be MH_EXECUTE (2); reject malformed headers.
    require(int.from_bytes(data[12:16], "little") == 2, f"{label} binary is not an executable Mach-O object")


def require_elf_x86_64(data: bytes, label: str) -> None:
    require(len(data) >= 64, f"{label} binary is too small to be an ELF executable")
    require(data[0:4] == b"\x7fELF", f"{label} binary is not an ELF executable")
    require(data[4] == 2, f"{label} binary is not a 64-bit (EI_CLASS) ELF object")
    require(data[5] == 1, f"{label} binary is not a little-endian (EI_DATA) ELF object")
    require(int.from_bytes(data[18:20], "little") == 62, f"{label} binary is not an x86-64 (e_machine) ELF object")


def parse_cargo_package(text: str) -> tuple[str, str]:
    name: str | None = None
    version: str | None = None
    in_package = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if re.fullmatch(r"\[.*\]", line):
            in_package = line == "[package]"
            continue
        if not in_package:
            continue
        match = re.fullmatch(r'(name|version)\s*=\s*"([^"]+)"', line)
        if match:
            if match.group(1) == "name":
                name = match.group(2)
            else:
                version = match.group(2)
    require(name is not None, "Cargo.toml [package] name is missing")
    require(version is not None, "Cargo.toml [package] version is missing")
    require(name == EXPECTED_PACKAGE_NAME, f"Cargo.toml package name changed: {name!r}")
    return name, version  # type: ignore[return-value]


def git_command(source_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(source_root), *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def git_identity(source_root: Path, field: str) -> str:
    try:
        completed = git_command(source_root, "rev-parse", field)
    except (OSError, ValueError, subprocess.SubprocessError):
        return "unavailable"
    value = (completed.stdout or "").strip()
    if completed.returncode != 0 or not value:
        return "unavailable"
    return value


def git_source_date(source_root: Path) -> str:
    try:
        completed = git_command(source_root, "show", "-s", "--format=%cI", "HEAD")
    except (OSError, ValueError, subprocess.SubprocessError):
        return "unavailable"
    value = (completed.stdout or "").strip()
    if completed.returncode != 0 or not value or "\n" in value:
        return "unavailable"
    try:
        import datetime as _dt

        return _dt.datetime.fromisoformat(value).astimezone(_dt.timezone.utc).isoformat(timespec="seconds")
    except ValueError:
        return "unavailable"


def verify_source_clean(resolved_root: Path) -> tuple[bool, dict]:
    if git_identity(resolved_root, "HEAD") == "unavailable":
        return False, {"note": "fails closed: source root is not a Git checkout"}
    try:
        status = git_command(resolved_root, "status", "--porcelain", "--untracked-files=all")
        worktree = git_command(resolved_root, "diff", "--quiet", "HEAD")
        staged = git_command(resolved_root, "diff", "--cached", "--quiet", "HEAD")
    except (OSError, ValueError, subprocess.SubprocessError):
        raise ReleaseError("cannot verify source cleanliness; refusing release without a clean tree") from None
    require(status.returncode == 0, "git status failed; refusing release without a clean tree")
    for label, completed in (("git diff HEAD", worktree), ("git diff --cached HEAD", staged)):
        require(completed.returncode in (0, 1), f"{label} failed; refusing release without a clean tree")
    dirty: list[str] = []
    allowed_untracked: list[str] = []
    for line in status.stdout.splitlines():
        if line.startswith("?? "):
            path = line[3:]
            if path == "target" or path.startswith("target/"):
                allowed_untracked.append(path)
                continue
        if line.strip():
            dirty.append(line)
    if worktree.returncode == 1:
        dirty.append("unstaged changes at HEAD")
    if staged.returncode == 1:
        dirty.append("staged changes at HEAD")
    require(not dirty, "source tree is not clean at HEAD; refusing release")
    return True, {"allowed_untracked_build_output": sorted(set(allowed_untracked))}


def build_deterministic_tarball(member_bytes: list[tuple[str, bytes, int]]) -> bytes:
    ordered = sorted(member_bytes, key=lambda item: item[0])
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for archive_path, data, mode in ordered:
            info = tarfile.TarInfo(name=archive_path)
            info.size = len(data)
            info.mtime = DETERMINISTIC_MTIME
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mode = mode
            info.type = tarfile.REGTYPE
            tar.addfile(info, io.BytesIO(data))
    tar_bytes = buffer.getvalue()
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", compresslevel=9, mtime=DETERMINISTIC_MTIME, fileobj=compressed) as gz:
        gz.write(tar_bytes)
    return compressed.getvalue()


def prepare_output_dir(output_dir: Path, resolved_root: Path) -> Path:
    require(bool(str(output_dir)), "--output-dir is required")
    candidate = output_dir.resolve(strict=False)
    try:
        candidate.relative_to(resolved_root)
        raise ReleaseError("--output-dir must lie outside the source tree")
    except ValueError:
        pass
    try:
        original = os.lstat(output_dir)
    except FileNotFoundError:
        original = None
    except OSError as error:
        raise ReleaseError("cannot inspect --output-dir") from error
    if original is not None:
        require(not stat.S_ISLNK(original.st_mode), "--output-dir must not be a symlink")
    try:
        existing = os.lstat(candidate)
    except FileNotFoundError:
        existing = None
    except OSError as error:
        raise ReleaseError("cannot inspect --output-dir") from error
    if existing is not None:
        require(stat.S_ISDIR(existing.st_mode), "--output-dir exists and is not a directory")
        try:
            entries = sorted(os.listdir(candidate))
        except OSError as error:
            raise ReleaseError("cannot inspect --output-dir") from error
        require(entries == [], "--output-dir must be new or empty; refusing to write into a non-empty directory")
    else:
        try:
            candidate.mkdir(parents=True, exist_ok=False)
        except OSError as error:
            raise ReleaseError("cannot create --output-dir") from error
    try:
        resolved_out = candidate.resolve(strict=True)
    except OSError as error:
        raise ReleaseError("--output-dir is not readable") from error
    try:
        resolved_out.relative_to(resolved_root)
        raise ReleaseError("--output-dir must lie outside the source tree")
    except ValueError:
        pass
    require(resolved_out.is_dir() and not resolved_out.is_symlink(), "--output-dir must be a real directory outside the source tree")
    return resolved_out


def write_exclusive(resolved_out: Path, name: str, data: bytes) -> Path:
    path = resolved_out / name
    require(path.parent == resolved_out, "refusing to write outside --output-dir")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags |= nofollow
    try:
        fd = os.open(path, flags, OUTPUT_FILE_MODE)
    except FileExistsError:
        raise ReleaseError(f"refusing to overwrite existing output file: {name}") from None
    except OSError as error:
        raise ReleaseError(f"cannot write {name}") from error
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except OSError as error:
        raise ReleaseError(f"cannot write {name}") from error
    return path


def generate_build_info(
    *,
    package_name: str,
    package_version: str,
    repository: str,
    repository_id: str,
    tag: str,
    commit: str,
    tree: str,
    source_date: str,
    cargo_lock_sha256: str,
    target: str,
    binary_sha256: str,
    binary_bytes: int,
    rustc_version: str,
    cargo_version: str,
    gate: dict,
) -> bytes:
    how_to_obtain = f"git clone https://github.com/{repository}.git && git checkout {tag}"
    record = {
        "schema": BUILD_INFO_SCHEMA,
        "distribution": "release-intent-authorized-draft-only",
        "release_intent_authorized": True,
        "publication_authorized": False,
        "final_release_controls_complete": False,
        "package": {"name": package_name, "version": package_version, "binary": EXPECTED_BINARY_NAME},
        "release": {
            "version": package_version,
            "tag": tag,
            "tag_policy": (gate.get("release_controls") or {}).get("tag_policy"),
            "exact_tag_required": (gate.get("release_controls") or {}).get("exact_tag_required"),
        },
        "owner_self_approval": gate.get("owner_self_approval"),
        "historical_release_intent": gate.get("historical_release_intent"),
        "target": target,
        "profile": EXPECTED_PROFILE,
        "source": {
            "repository": repository,
            "repository_id": repository_id,
            "tag": tag,
            "commit": commit,
            "tree": tree,
            "source_date_utc": source_date,
            "source_root_included": False,
        },
        "build": {
            "command": EXPECTED_CARGO_COMMAND,
            "command_is_documented": True,
            "verified_by_this_script": False,
            "rustc_version": rustc_version,
            "cargo_version": cargo_version,
            "cargo_lock_sha256": cargo_lock_sha256,
            "pinned_toolchain": EXPECTED_TOOLCHAIN,
            "toolchain_observation": "exact version lines observed in the CI build jobs and asserted again by this offline packager against the pinned 1.94.1 lines; the packager did not independently execute rustc or cargo",
        },
        "toolchain": {
            "rustc": rustc_version,
            "cargo": cargo_version,
            "pinned": EXPECTED_TOOLCHAIN,
            "rustc_version": rustc_version,
            "cargo_version": cargo_version,
            "pinned_toolchain": EXPECTED_TOOLCHAIN,
        },
        "corresponding_source": {
            "repository": repository,
            "tag": tag,
            "commit": commit,
            "tree": tree,
            "included_in_archive": False,
            "how_to_obtain": how_to_obtain,
        },
        "binary": {
            "sha256": binary_sha256,
            "bytes": binary_bytes,
            "target": target,
        },
        "dependencies": {
            "lockfile": CARGO_LOCK_REL,
            "lockfile_sha256": cargo_lock_sha256,
            "third_party_notices": "THIRD_PARTY_LICENSES.md",
            "license": "LICENSE-MIT",
        },
        "install": {
            "binary": EXPECTED_BINARY_NAME,
            "mode": oct(FILE_MODE_BIN),
            "instructions": "INSTALL.md",
        },
        "binary_build_linkage": BINARY_BUILD_LINKAGE_NOTE,
        "rights_gate": {
            "rights_decision": gate.get("rights_decision"),
            "notice_applicability": gate.get("notice_applicability"),
            "blocking_open": list(gate.get("blocking_open") or []),
            "release_intent_authorization": (gate.get("release_intent_authorization") or {}).get("status"),
            "technical_notice_review": (gate.get("technical_notice_review") or {}).get("reviewed_by"),
            "release_controls": (gate.get("release_controls") or {}).get("status"),
        },
        "release_controls": {
            "workflow": (gate.get("release_controls") or {}).get("workflow"),
            "environment": (gate.get("release_controls") or {}).get("environment"),
            "environment_required_reviewer": (gate.get("release_controls") or {}).get("environment_required_reviewer"),
            "environment_prevent_self_review": (gate.get("release_controls") or {}).get("environment_prevent_self_review"),
            "environment_reviewer_owner_id": (gate.get("release_controls") or {}).get("environment_reviewer_owner_id"),
            "environment_reviewer_owner_login": (gate.get("release_controls") or {}).get("environment_reviewer_owner_login"),
            "independent_environment_review": (gate.get("release_controls") or {}).get("independent_environment_review"),
            "owner_self_approval": (gate.get("release_controls") or {}).get("owner_self_approval"),
            "owner_self_approval_policy": (gate.get("release_controls") or {}).get("owner_self_approval_policy"),
            "publication_mode": (gate.get("release_controls") or {}).get("publication_mode"),
            "manual_publish_required": (gate.get("release_controls") or {}).get("manual_publish_required"),
            "final_release_controls_complete": (gate.get("release_controls") or {}).get("final_release_controls_complete"),
            "tag_policy": (gate.get("release_controls") or {}).get("tag_policy"),
            "exact_tag_required": (gate.get("release_controls") or {}).get("exact_tag_required"),
            "immutable_release": (gate.get("release_controls") or {}).get("immutable_release"),
            "immutable_tag_required": (gate.get("release_controls") or {}).get("immutable_tag_required"),
            "tag_ruleset_exact_scope": (gate.get("release_controls") or {}).get("tag_ruleset_exact_scope"),
            "tag_creation_ruleset_name": (gate.get("release_controls") or {}).get("tag_creation_ruleset_name"),
            "tag_creation_rule_required": (gate.get("release_controls") or {}).get("tag_creation_rule_required"),
            "tag_creation_bypass_actors_allowed": (gate.get("release_controls") or {}).get("tag_creation_bypass_actors_allowed"),
            "tag_immutability_ruleset_name": (gate.get("release_controls") or {}).get("tag_immutability_ruleset_name"),
            "tag_immutability_scope": (gate.get("release_controls") or {}).get("tag_immutability_scope"),
            "tag_immutability_bypass_actors_allowed": (gate.get("release_controls") or {}).get("tag_immutability_bypass_actors_allowed"),
            "attestations": list((gate.get("release_controls") or {}).get("attestations") or []),
            "immutable_setting_admin_verification_required": (gate.get("release_controls") or {}).get("immutable_setting_admin_verification_required"),
            "exact_tag_main_ci": (gate.get("release_controls") or {}).get("exact_tag_main_ci"),
        },
    }
    return (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")


def generate_install_md(
    *,
    package_name: str,
    package_version: str,
    repository: str,
    tag: str,
    commit: str,
    tree: str,
    source_date: str,
    cargo_lock_sha256: str,
    target: str,
) -> bytes:
    how_to_obtain = f"git clone https://github.com/{repository}.git && git checkout {tag}"
    archive_name = MACOS_ARCHIVE if target == MACOS_TARGET else LINUX_ARCHIVE
    root_dir = MACOS_ROOT if target == MACOS_TARGET else LINUX_ROOT
    if target == MACOS_TARGET:
        platform_section = f"""## macOS ARM64 notes

- This package contains a macOS ARM64 (`aarch64-apple-darwin`) binary that is
  ad-hoc signed only. It is NOT Developer ID signed and NOT notarized.
- Gatekeeper may block or quarantine the binary on first run. If macOS blocks
  launch, stop and retain the exact warning, OS version, download source, and
  quarantine details. Do NOT disable Gatekeeper, strip quarantine, alter
  system policy, or silently bypass the block. A local
  launch is not proof that a quarantined download will launch.
- No installer, privileged helper, or system modification is performed by this
  archive. Never require sudo. Install only the verified `astatine` binary to
  a user-owned path such as `$HOME/.local/bin` after checking that directory
  and its ownership.
- Verify only this platform archive against `SHA256SUMS` (which covers both
  platform archives) with:
  `grep -F "  {archive_name}" SHA256SUMS | shasum -a 256 -c -`
  Always verify the GitHub build-provenance attestations for the exact tag and
  confirm the release is immutable (`gh release view <tag> --json isImmutable --jq .isImmutable`
  prints `true`) before installing; never trust the archive alone."""
    else:
        platform_section = f"""## Linux x86_64 notes

- This package contains a Linux x86_64 (`x86_64-unknown-linux-gnu`) binary
  built for glibc-based Ubuntu 24.04. Other distributions or musl-based
  systems are not qualified by this package.
- Paid mining requires an unlocked Secret Service (D-Bus secret collection);
  without it, paid-mining key operations fail. The binary never moves wallets
  or credentials; keep configuration, keystores, and journals in place and
  replace only the binary on upgrade.
- CUDA/GPU acceleration is not qualified by this package; GPU paths remain
  untested for this release and CPU mining is the only qualified path.
- Never require sudo. Install only to a user-owned path such as
  `$HOME/.local/bin` after checking that directory and its ownership.
- Verify only this platform archive against `SHA256SUMS` (which covers both
  platform archives) with:
  `grep -F "  {archive_name}" SHA256SUMS | sha256sum -c -`
  Always verify the GitHub build-provenance attestations for the exact tag and
  confirm the release is immutable (`gh release view <tag> --json isImmutable --jq .isImmutable`
  prints `true`) before installing."""
    if target == MACOS_TARGET:
        verify_command = f'\n   `grep -F "  {archive_name}" SHA256SUMS | shasum -a 256 -c -`'
    else:
        verify_command = f'\n   `grep -F "  {archive_name}" SHA256SUMS | sha256sum -c -`'
    text = f"""# Astatine miner {package_version} — {target} install notes

Testnet only. This is Astatine `{tag}` for `{target}`. No mainnet deployment
or paid-operation risk acceptance is authorized by this package. Verify
`SHA256SUMS`, the GitHub build-provenance attestations for the exact tag,
and the release's immutable status before installing; never trust the archive
alone. This release used an explicit owner self-approval policy; no independent
human reviewer approved it, and no separation of duties is claimed. Ownership
and redistribution authority remain owner-attested and have not been
independently verified.

- Package: {package_name}
- Binary: {EXPECTED_BINARY_NAME}
- Version: {package_version}
- Tag: {tag}
- Target: {target}
- Profile: {EXPECTED_PROFILE}
- Archive root: {root_dir}/ (exactly five regular files inside)

{platform_section}

## Exact source identity

- Repository: {repository}
- Tag: {tag}
- Commit: {commit}
- Tree: {tree}
- Source date (commit timestamp): {source_date}
- The corresponding source tree is NOT inside this archive. Obtain it with:
  `{how_to_obtain}`

## Inspect before extracting

1. List contents without extracting:
   `tar -tzf {archive_name}`
2. Require exactly one top-level root directory `{root_dir}/` containing
   exactly five regular files: `{root_dir}/astatine` (0755),
   `{root_dir}/LICENSE-MIT`, `{root_dir}/THIRD_PARTY_LICENSES.md`,
   `{root_dir}/BUILD-INFO.json`, `{root_dir}/INSTALL.md` (0644).
3. Reject extra, hidden, absolute, traversal, duplicate, linked, or
   special-file entries, or any unexpected mode. A `tar -tzf` fixture check
   still applies with the root prefix: reject any entry containing
   `tests/fixtures`, `PROVENANCE.json`, or any fixture basename.

## Install (no sudo, user-owned path only)

1. Verify only this platform archive against `SHA256SUMS` (which covers both
   platform archives; check this archive's row, never trust an archive alone):{verify_command}
2. Verify the GitHub build-provenance attestations for the exact tag and
   confirm the release is immutable (`gh release view <tag> --json isImmutable --jq .isImmutable`
   prints `true`) before installing.
3. Extract as your ordinary user into a new empty private directory, never
   with sudo. For example:
   `mkdir -m 700 "$HOME/{root_dir}-extract" && tar -xzf {archive_name} -C "$HOME/{root_dir}-extract"`
4. Check the destination directory exists, is user-owned, and is not a
   symlink. Do not overwrite an active miner or an unexpected existing
   executable or symlink. For example:
   `mkdir -p "$HOME/.local/bin"`
   `test ! -e "$HOME/.local/bin/astatine" && test ! -L "$HOME/.local/bin/astatine"`
   `install -m 755 "$HOME/{root_dir}-extract/{root_dir}/astatine" "$HOME/.local/bin/astatine"`
5. Confirm: `"$HOME/.local/bin/astatine" --version` (expect {package_version}).

## Upgrade (preserve user state)

1. Stop the running miner first.
2. Keep your existing configuration, wallets, keystores, credentials, and
   transaction journals exactly where they are.
3. Replace ONLY the `astatine` binary. Never overwrite, delete, reinitialize,
   or migrate state files to satisfy a new binary.
4. Downgrade compatibility is not guaranteed; keep a recoverable copy of your
   prior binary and state before upgrading.

## Corresponding source and dependencies

- Obtain the exact corresponding source (not included here):
  `{how_to_obtain}`
- Dependency pins: {CARGO_LOCK_REL} SHA-256 `{cargo_lock_sha256}`.
- Third-party notices: {root_dir}/THIRD_PARTY_LICENSES.md (in this archive).
- License: {root_dir}/LICENSE-MIT (in this archive).

## Build linkage

{BINARY_BUILD_LINKAGE_NOTE}.
"""
    return text.encode("utf-8")


def require_toolchain_line(value: object, label: str, expected: str) -> str:
    line = require_string(value, label)
    require(line == expected, f"{label} must be exactly {expected!r}")
    return line


def run(
    *,
    source_root: Path,
    output_dir: Path,
    tag: str,
    repository_id: str,
    macos_binary: Path,
    linux_binary: Path,
    rustc_version: str | None = None,
    cargo_version: str | None = None,
) -> dict:
    require_string(tag, "--tag")
    require_string(repository_id, "--repository-id")
    require(re.fullmatch(r"[0-9]+", repository_id) is not None, "--repository-id must be digits")
    require(tag == RELEASE_NOTES_TAG, f"--tag must be exactly {RELEASE_NOTES_TAG}")
    rustc_version = require_toolchain_line(rustc_version, "--rustc-version", EXPECTED_RUSTC_VERSION_LINE)
    cargo_version = require_toolchain_line(cargo_version, "--cargo-version", EXPECTED_CARGO_VERSION_LINE)
    try:
        resolved_root = source_root.resolve(strict=False)
    except (OSError, ValueError, RuntimeError):
        raise ReleaseError("source root is not readable; refusing release") from None
    require(resolved_root.is_dir(), "source root is not a directory")
    try:
        resolved_root = resolved_root.resolve(strict=True)
    except (OSError, ValueError, RuntimeError):
        raise ReleaseError("source root is not readable") from None

    # Gate: owner-authorized release-intent state is required; blocked fails closed.
    # Final publication is never authorized by this packager.
    gate_module = _load_gate_module()
    try:
        gate = gate_module.load_gate(resolved_root, require_release_version=True)
    except Exception as error:
        raise ReleaseError(str(error)) from error
    require(gate.get("state") == "release-intent-authorized", "release requires the release-intent-authorized gate state; blocked gates fail closed")
    require(gate.get("release_intent_authorized") is True, "release requires release_intent_authorized true")
    require(gate.get("publication_authorized") is False, "release must not claim final publication authorization")
    require(gate.get("final_release_controls_complete") is False, "release requires final release controls to remain outstanding")
    require(list(gate.get("targets") or []) == [MACOS_TARGET, LINUX_TARGET], "release gate targets changed")
    require(gate.get("source_status") == "RELEASE-INTENT-AUTHORIZED" and gate.get("binary_status") == "RELEASE-INTENT-AUTHORIZED", "release requires RELEASE-INTENT-AUTHORIZED source and binary distribution")

    # Source identity: repository, package version, tag binding, clean tree.
    repository = gate.get("repository")
    require(repository == EXPECTED_REPOSITORY, f"release repository changed: {repository!r}")
    package_version = gate.get("package_version")
    require(
        package_version == EXPECTED_RELEASE_VERSION,
        f"Cargo package version must be exactly {EXPECTED_RELEASE_VERSION!r}",
    )
    require(tag == f"v{package_version}", f"--tag {tag!r} does not match Cargo package version {package_version!r}")
    lock_bytes = read_confined_bytes(resolved_root, CARGO_LOCK_REL, "cargo lockfile")
    lock_sha = sha256_hex(lock_bytes)
    cargo_text = read_confined_bytes(resolved_root, CARGO_TOML_REL, "cargo manifest").decode("utf-8")
    _, parsed_version = parse_cargo_package(cargo_text)
    require(parsed_version == package_version, "Cargo package version changed during release")

    source_verified, source_status = verify_source_clean(resolved_root)
    require(source_verified, "source tree is not clean at HEAD; refusing release")

    commit = git_identity(resolved_root, "HEAD")
    tree = git_identity(resolved_root, "HEAD^{tree}")
    source_date = git_source_date(resolved_root)
    require(commit != "unavailable", "commit identity is unavailable")
    require(tree != "unavailable", "tree identity is unavailable")
    require(source_date != "unavailable", "commit source date is unavailable")
    # Tag must exist and resolve to HEAD (fail closed on missing/moved tags).
    try:
        tag_commit_proc = git_command(resolved_root, "rev-list", "-n", "1", tag)
        head_proc = git_command(resolved_root, "rev-parse", "HEAD")
    except (OSError, ValueError, subprocess.SubprocessError):
        raise ReleaseError("cannot verify release tag; refusing release") from None
    require(tag_commit_proc.returncode == 0, f"release tag does not exist: {tag}")
    tag_commit = (tag_commit_proc.stdout or "").strip()
    head_commit = (head_proc.stdout or "").strip() if head_proc.returncode == 0 else ""
    require(tag_commit and head_commit and tag_commit == head_commit and commit == head_commit, "release tag does not resolve to HEAD; refusing release")

    # Binaries: validate headers without executing.
    macos_data = read_input_binary(macos_binary, "macOS")
    linux_data = read_input_binary(linux_binary, "Linux")
    require_macho_arm64(macos_data, "macOS")
    require_elf_x86_64(linux_data, "Linux")

    license_data = read_confined_bytes(resolved_root, LICENSE_MIT_REL, "license")
    third_party_data = read_confined_bytes(resolved_root, THIRD_PARTY_REL, "third-party notices")

    # Package each target deterministically with exactly five members under a
    # single platform root directory (the nonpublishing dry-run remains flat;
    # only the authorized release uses the root prefix).
    outputs: list[dict] = []
    archives: list[tuple[str, bytes]] = []
    for target, binary_data, filename, root_dir in (
        (MACOS_TARGET, macos_data, MACOS_ARCHIVE, MACOS_ROOT),
        (LINUX_TARGET, linux_data, LINUX_ARCHIVE, LINUX_ROOT),
    ):
        build_info = generate_build_info(
            package_name=EXPECTED_PACKAGE_NAME,
            package_version=package_version,
            repository=repository,
            repository_id=repository_id,
            tag=tag,
            commit=commit,
            tree=tree,
            source_date=source_date,
            cargo_lock_sha256=lock_sha,
            target=target,
            binary_sha256=sha256_hex(binary_data),
            binary_bytes=len(binary_data),
            rustc_version=rustc_version,
            cargo_version=cargo_version,
            gate=gate,
        )
        install_md = generate_install_md(
            package_name=EXPECTED_PACKAGE_NAME,
            package_version=package_version,
            repository=repository,
            tag=tag,
            commit=commit,
            tree=tree,
            source_date=source_date,
            cargo_lock_sha256=lock_sha,
            target=target,
        )
        member_inputs = [
            (f"{root_dir}/astatine", binary_data, FILE_MODE_BIN),
            (f"{root_dir}/LICENSE-MIT", license_data, FILE_MODE_DOC),
            (f"{root_dir}/THIRD_PARTY_LICENSES.md", third_party_data, FILE_MODE_DOC),
            (f"{root_dir}/BUILD-INFO.json", build_info, FILE_MODE_DOC),
            (f"{root_dir}/INSTALL.md", install_md, FILE_MODE_DOC),
        ]
        # Refuse fixtures/forbidden globs even though inputs are fixed: fail
        # closed if any member name collides. The root prefix does not weaken
        # the check: basenames and full prefixed paths are both screened, so
        # the workflow `tar -tzf` fixture check keeps working with the prefix.
        expected_prefixed = sorted(f"{root_dir}/{name}" for name in EXPECTED_BASENAMES)
        for archive_path, _, _ in member_inputs:
            basename = archive_path.rsplit("/", 1)[-1]
            require(basename in EXPECTED_BASENAMES, f"unexpected archive member basename: {basename}")
            require(archive_path in expected_prefixed, f"unexpected archive member: {archive_path}")
            # Screen both the full prefixed path and the basename against
            # forbidden globs and fixture identities.
            for candidate in (archive_path, basename):
                for pattern in ("tests/fixtures/**", "**/PROVENANCE.json"):
                    matched = False
                    if candidate == pattern:
                        matched = True
                    elif pattern.endswith("/**") and (candidate == pattern[:-3] or candidate.startswith(pattern[:-3] + "/")):
                        matched = True
                    elif pattern.startswith("**/"):
                        suffix = pattern[3:]
                        if "/" not in suffix and (candidate == suffix or candidate.endswith("/" + suffix)):
                            matched = True
                    require(not matched, f"archive member matches a forbidden glob: {archive_path}")
                require("PROVENANCE.json" not in candidate, f"archive member must never carry provenance inventory: {archive_path}")
            require(basename not in ("AstatineMiner.json", "AstatineGenesisCoordinator.json", "MockAST.json", "synthetic-injective-virtual-receipt.json", "PROVENANCE.json"), f"archive member allows a fixture into the release archive: {archive_path}")
        require(sorted(p[0] for p in member_inputs) == expected_prefixed, "archive member set changed; refusing release")
        archive_bytes = build_deterministic_tarball(member_inputs)
        archive_sha = sha256_hex(archive_bytes)
        member_records = []
        for archive_path, data, mode in sorted(member_inputs, key=lambda item: item[0]):
            basename = archive_path.rsplit("/", 1)[-1]
            entry: dict = {
                "archive_path": archive_path,
                "sha256": sha256_hex(data),
                "bytes": len(data),
                "mode": oct(mode),
            }
            if basename == "astatine":
                entry.update({"source": "prebuilt-binary", "generated": False, "target": target})
            elif basename in ("BUILD-INFO.json", "INSTALL.md"):
                entry.update({"source": f"generated:{basename}", "generated": True, "generator": "support/release/build-release.py"})
            else:
                entry.update({"source": basename, "generated": False})
            member_records.append(entry)
        outputs.append(
            {
                "target": target,
                "filename": filename,
                "sha256": archive_sha,
                "bytes": len(archive_bytes),
                "members": member_records,
                "binary_sha256": sha256_hex(binary_data),
                "binary_bytes": len(binary_data),
                "build_info_sha256": sha256_hex(build_info),
                "install_sha256": sha256_hex(install_md),
            }
        )
        archives.append((filename, archive_bytes))

    resolved_out = prepare_output_dir(output_dir, resolved_root)
    for filename, archive_bytes in archives:
        write_exclusive(resolved_out, filename, archive_bytes)
    checksums_text = "".join(f"{entry['sha256']}  {entry['filename']}\n" for entry in sorted(outputs, key=lambda e: e["filename"]))
    write_exclusive(resolved_out, "SHA256SUMS", checksums_text.encode("utf-8"))

    record = {
        "schema": "astatine-release-provenance/v1",
        "tag": tag,
        "repository": repository,
        "repository_id": repository_id,
        "commit": commit,
        "tree": tree,
        "source_date": source_date,
        "package_name": EXPECTED_PACKAGE_NAME,
        "package_version": package_version,
        "release": {
            "version": package_version,
            "tag": tag,
            "tag_policy": (gate.get("release_controls") or {}).get("tag_policy"),
            "exact_tag_required": (gate.get("release_controls") or {}).get("exact_tag_required"),
        },
        "owner_self_approval": gate.get("owner_self_approval"),
        "historical_release_intent": gate.get("historical_release_intent"),
        "rights_decision": gate.get("rights_decision"),
        "cargo_lock_sha256": lock_sha,
        "toolchain": {
            "rustc": rustc_version,
            "cargo": cargo_version,
            "pinned": EXPECTED_TOOLCHAIN,
            "rustc_version": rustc_version,
            "cargo_version": cargo_version,
            "pinned_toolchain": EXPECTED_TOOLCHAIN,
        },
        "targets": [MACOS_TARGET, LINUX_TARGET],
        "archives": outputs,
        "gate": {
            "rights_decision": gate.get("rights_decision"),
            "notice_applicability": gate.get("notice_applicability"),
            "blocking_open": [],
            "source_status": gate.get("source_status"),
            "binary_status": gate.get("binary_status"),
            "release_intent_authorization": (gate.get("release_intent_authorization") or {}).get("status"),
            "technical_notice_review": (gate.get("technical_notice_review") or {}).get("reviewed_by"),
            "release_controls": (gate.get("release_controls") or {}).get("status"),
        },
        "release_intent_authorized": True,
        "publication_authorized": False,
        "final_release_controls_complete": False,
        "git_verified": True,
        "source_clean_at_head": True,
        "source_clean_status": source_status,
        "binary_build_linkage": BINARY_BUILD_LINKAGE_NOTE,
        "provenance_path": PROVENANCE_REL,
        "inventory_path": INVENTORY_REL,
        "notes": (
            "Release-intent offline release packaging only (draft-only): no final publication, upload, tag creation, attestation dispatch, or external release execution was performed by this script. "
            "GitHub environment protection, exact-commit main CI, tag existence, immutable-release setting verification, and attestations are enforced by the release workflow preflight, build jobs, and owner manual publication steps before any publication; the release path is draft-only. "
            "Binary format checks here do not prove binary identity or source linkage; the workflow build jobs plus GitHub build provenance are the linkage control. "
            "This record contains no absolute checkout path, no raw invocation, and no verbatim environment path; binary inputs are recorded by hash only. "
            "Bit-for-bit reproducibility across hosts is not claimed."
        ),
    }
    # Fail closed on absolute-path leakage before writing.
    dumped = json.dumps(record, indent=2, sort_keys=True)
    require(str(resolved_root) not in dumped, "provenance must not contain absolute checkout paths")
    # Input binary paths are never recorded, but double-check no invocation leakage.
    require("--macos-binary" not in dumped and "--linux-binary" not in dumped, "provenance must not contain raw invocation")
    write_exclusive(resolved_out, "release-provenance.json", (dumped + "\n").encode("utf-8"))

    return {
        "tag": tag,
        "repository": repository,
        "repository_id": repository_id,
        "commit": commit,
        "tree": tree,
        "package_version": package_version,
        "cargo_lock_sha256": lock_sha,
        "archives": outputs,
        "release_intent_authorized": True,
        "publication_authorized": False,
        "final_release_controls_complete": False,
        "gate_state": gate.get("state"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline release-intent dual-platform release packager (draft-only, no publication).")
    parser.add_argument("--tag", required=True, help="exact release tag, e.g. v0.1.0-testnet.3")
    parser.add_argument("--repository-id", required=True, help="numeric GitHub repository id")
    parser.add_argument("--macos-binary", required=True, type=Path, help="path to prebuilt macOS ARM64 binary")
    parser.add_argument("--linux-binary", required=True, type=Path, help="path to prebuilt Linux x86_64 binary")
    parser.add_argument("--rustc-version", required=True, help="exact `rustc --version` line observed in the CI build jobs")
    parser.add_argument("--cargo-version", required=True, help="exact `cargo --version` line observed in the CI build jobs")
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = run(
            source_root=args.source_root,
            output_dir=args.output_dir,
            tag=args.tag,
            repository_id=args.repository_id,
            macos_binary=args.macos_binary,
            linux_binary=args.linux_binary,
            rustc_version=args.rustc_version,
            cargo_version=args.cargo_version,
        )
    except ReleaseError as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}, indent=2), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"status": "FAIL", "error": "filesystem error"}, indent=2), file=sys.stderr)
        return 1
    public_result = {
        "status": "PASS",
        "tag": result["tag"],
        "package_version": result["package_version"],
        "cargo_lock_sha256": result["cargo_lock_sha256"],
        "release_intent_authorized": result["release_intent_authorized"],
        "publication_authorized": result["publication_authorized"],
        "final_release_controls_complete": result["final_release_controls_complete"],
        "archives": [
            {"filename": entry["filename"], "sha256": entry["sha256"], "bytes": entry["bytes"], "target": entry["target"]}
            for entry in result["archives"]
        ],
        "provenance_file": "release-provenance.json",
        "checksums_file": "SHA256SUMS",
        "note": "absolute filesystem paths are withheld from stdout; open the files in the requested --output-dir",
    }
    print(json.dumps(public_result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
