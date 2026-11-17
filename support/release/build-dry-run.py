#!/usr/bin/env python3
"""Offline deterministic Linux release dry-run builder (no publication).

Reads exactly tests/fixtures/PROVENANCE.json and
support/release/distribution-inventory.json (canonical paths only; no
overrides exist so a caller cannot substitute an old blocked copy after the
real gate changes), independently re-checks the blocked rights gate against
exact canonical strings, requires the full source tree (tracked changes and
non-ignored untracked files) to be clean at HEAD, and builds a deterministic
tar.gz from the explicit allowlist only:
the built binary plus LICENSE-MIT, THIRD_PARTY_LICENSES.md, and two
generated members (BUILD-INFO.json, INSTALL.md) produced deterministically in
memory. No fixture may enter the archive.

The script is offline and stdlib-only. It never uses the network, never
modifies the source tree, and writes only to the required --output-dir, which
must be new or empty and lie outside the source tree. Output files are created
exclusively (no overwrite, no symlink following).

Gate semantics (fail closed):
  * --mode release always fails: no authorized publisher exists.
  * --mode dry-run fails unless the gate matches the exact canonical blocked
    text (publication_decision, checklist status, NOTICE applicability, and
    the RIGHTS-02..RIGHTS-05 action/owner/evidence records byte-for-byte),
    both source and binary distribution are BLOCKED, the archive allowlist is
    exactly the three expected source members plus exactly the two expected
    generated members, every provenance fixture declares
    release_archive_member false, the required forbidden globs are present,
    and no member matches a forbidden glob or fixture path.
  * The limited review/CI branch-push authorization
    (review_ci_branch_push_authorization) must match the exact canonical object
    byte-for-byte in both gate files; public repository visibility authorizes
    nothing beyond pushing the remediation branch for review and CI. RIGHTS-02
    through RIGHTS-05 stay OPEN and blocking, source/binary distribution stay
    BLOCKED, and no tag, release, or attestation dispatch is authorized.
  * The full tracked source tree (including both gate files) must be clean
    at HEAD; tracked changes and non-ignored untracked files are rejected.
    Git-ignored files are not inspected by this check; target/ is the expected
    build output and the only explicitly allowed untracked path. A clean
    tree does NOT prove the archived binary was built from HEAD; that linkage
    is workflow-build-only (fresh checkout, then build) and is recorded as
    unverified (see binary_build_linkage).
  * The observed `rustc --version` and `cargo --version` output must be
    exactly the official single-line Rust/Cargo 1.94.1 lines
    (`rustc 1.94.1 (e408947bf 2026-03-25)` and
    `cargo 1.94.1 (29ea6fb6a 2026-03-24)`), with at most one trailing LF or
    CRLF. Capture is bounded to 513 bytes with a timeout; extra lines,
    control characters, oversize output, nonzero exit, and timeouts fail
    closed. This is a format check, not toolchain or publisher authentication.
    The bounded capture path uses POSIX pipe `select`; it is verified on macOS
    and intended for the Linux x86_64 dry-run, and is not supported for
    Windows execution.
  * The archived binary must be an ELF64 little-endian x86_64 object before
    it is archived.
  * release-provenance.json always records publication_authorized: false.

The GitHub workflow performs no artifact attestation and no attestation
dispatch occurs. The inventory explicitly records workflow attestation
dispatch as not authorized, so the dry-run creates only local files and
requests no OIDC identity. No transparency-log entry is created by this
script, which itself signs no external release binary and uploads no
release asset. Local release-provenance.json records no absolute checkout
path and no raw invocation, to avoid introducing identifying data into
artifacts that operators might copy; legitimate provenance (commit, tree,
source date, toolchain, lock hash, artifact and member hashes, gate state)
is preserved.

Usage:
    python3 -B support/release/build-dry-run.py \
        --mode dry-run --output-dir /tmp/astatine-dry-run-out
"""

from __future__ import annotations

import argparse
import datetime
import fnmatch
import gzip
import hashlib
import io
import json
import math
import os
import re
import select
import stat
import subprocess
import sys
import tarfile
import time
from pathlib import Path, PurePosixPath

PROVENANCE_REL = "tests/fixtures/PROVENANCE.json"
INVENTORY_REL = "support/release/distribution-inventory.json"
CARGO_TOML_REL = "Cargo.toml"
REPOSITORY_REL = "support/release-repository.txt"
CARGO_LOCK_REL = "Cargo.lock"
EXPECTED_INVENTORY_SCHEMA = "astatine-distribution-inventory/v1"
EXPECTED_GATE_SOURCE = "tests/fixtures/PROVENANCE.json"
EXPECTED_PUBLICATION_DECISION = (
    "BLOCKED pending review of rights and notice applicability; "
    "first-party ownership is owner-attested and not independently verified."
)
EXPECTED_NOTICE_APPLICABILITY = "UNRESOLVED"
EXPECTED_CHECKLIST_STATUS = "OPEN \u2014 publication remains BLOCKED"
EXPECTED_BRANCH_PUSH_AUTHORIZATION = {
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
EXPECTED_BLOCKING_OPEN = ["RIGHTS-02", "RIGHTS-03", "RIGHTS-04", "RIGHTS-05"]
EXPECTED_BLOCKING_OPEN_SET = frozenset(EXPECTED_BLOCKING_OPEN)
EXPECTED_BLOCKING_ITEMS = {
    "RIGHTS-02": {
        "action": (
            "Decide whether Apache-2.0 NOTICE propagation applies to each distributed "
            "artifact. The contract fixtures are not release-archive members, so any "
            "obligation follows source redistribution of the fixtures rather than the "
            "miner binary."
        ),
        "owner": "project owner and release approver",
        "evidence": (
            "rights_review.copyright_evidence; fixtures FIX-01 and FIX-02 both set "
            "release_archive_member to false."
        ),
    },
    "RIGHTS-03": {
        "action": (
            "If the two first-party contract fixtures remain in the public source tree, "
            "add the Apache-2.0 license text and a copyright statement for them, or "
            "remove those fixtures from the public tree."
        ),
        "owner": "project owner",
        "evidence": (
            "tests/fixtures ships OPENZEPPELIN_LICENSE.txt only; no Apache-2.0 license "
            "text accompanies FIX-01 or FIX-02."
        ),
    },
    "RIGHTS-04": {
        "action": (
            "Confirm authorship and redistribution authority for MockAST and keep the "
            "OpenZeppelin MIT notice with any redistribution of it."
        ),
        "owner": "project owner",
        "evidence": "FIX-03 license.declaration_evidence; legal_artifacts OPENZEPPELIN_LICENSE.txt.",
    },
    "RIGHTS-05": {
        "action": (
            "Record the final rights and notice decision in tests/fixtures/README.md and "
            "this inventory before publishing the repository or a release archive."
        ),
        "owner": "release approver",
        "evidence": "rights_review.publication_decision is BLOCKED.",
    },
}
EXPECTED_TARGET = "x86_64-unknown-linux-gnu"
EXPECTED_TOOLCHAIN = "1.94.1"
# Strict complete-line toolchain identity. Only the official single-line
# `rustc --version` / `cargo --version` outputs for Rust 1.94.1 are accepted,
# optionally followed by a single trailing LF or CRLF at capture time. The
# recorded provenance always holds the canonical line without any trailing
# newline. This does not authenticate the toolchain or publisher; it only
# rejects synthetic prefix-plus-marker output from reaching provenance.
EXPECTED_RUSTC_VERSION_LINE = "rustc 1.94.1 (e408947bf 2026-03-25)"
EXPECTED_CARGO_VERSION_LINE = "cargo 1.94.1 (29ea6fb6a 2026-03-24)"
MAX_TOOLCHAIN_OUTPUT_BYTES = 512
_RUSTC_VERSION_LINE_RE = re.compile(r"rustc 1\.94\.1 \(e408947bf 2026-03-25\)(?:\r\n|\n)?")
_CARGO_VERSION_LINE_RE = re.compile(r"cargo 1\.94\.1 \(29ea6fb6a 2026-03-24\)(?:\r\n|\n)?")
EXPECTED_PACKAGE_NAME = "astatine-cli-rust"
EXPECTED_BINARY_NAME = "astatine"
EXPECTED_BUILD_PROFILE = "release"
EXPECTED_CARGO_COMMAND = "cargo build --locked --release"
EXPECTED_REPOSITORY = "Jecta-ai/astatine-miner"
EXPECTED_BUILD_INFO_GENERATOR = "support/release/build-dry-run.py"
EXPECTED_GENERATED_MEMBERS = (
    ("BUILD-INFO.json", EXPECTED_BUILD_INFO_GENERATOR),
    ("INSTALL.md", EXPECTED_BUILD_INFO_GENERATOR),
)
EXPECTED_GENERATED_PATHS = frozenset(archive for archive, _ in EXPECTED_GENERATED_MEMBERS)
EXPECTED_ARCHIVE_MEMBERS = (
    ("target/release/astatine", "astatine"),
    ("LICENSE-MIT", "LICENSE-MIT"),
    ("THIRD_PARTY_LICENSES.md", "THIRD_PARTY_LICENSES.md"),
)
BINARY_SOURCE = "target/release/astatine"
EXPECTED_ARCHIVE_PATHS = frozenset(archive for _, archive in EXPECTED_ARCHIVE_MEMBERS)
EXPECTED_ALL_ARCHIVE_PATHS = ["BUILD-INFO.json", "INSTALL.md", "LICENSE-MIT", "THIRD_PARTY_LICENSES.md", "astatine"]
EXPECTED_FIXTURE_PATHS = frozenset(
    {
        "tests/fixtures/AstatineMiner.json",
        "tests/fixtures/AstatineGenesisCoordinator.json",
        "tests/fixtures/MockAST.json",
        "tests/fixtures/synthetic-injective-virtual-receipt.json",
    }
)
REQUIRED_FORBIDDEN_GLOBS = frozenset({"tests/fixtures/**", "**/PROVENANCE.json"})
ATTESTED_RIGHTS = "OWNER-ATTESTED \u2014 not independently verified"
ARTIFACT_FILENAME = "astatine-x86_64-unknown-linux-gnu.dry-run.tar.gz"
FILE_MODE_DOC = 0o644
FILE_MODE_BIN = 0o755
DETERMINISTIC_MTIME = 0
OUTPUT_FILE_MODE = 0o600
BUILD_INFO_SCHEMA = "astatine-build-info/v1"
BUILD_INFO_DISTRIBUTION = "dry-run-no-publication"
BINARY_BUILD_LINKAGE_NOTE = (
    "unverified: a clean source tree does not prove the archived binary was built "
    "from HEAD; linkage is workflow-build-only (fresh checkout, then build) and is "
    "not independently verified by this script"
)


class DryRunError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DryRunError(message)


def require_object(value: object, label: str) -> dict:
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def require_list(value: object, label: str) -> list:
    require(isinstance(value, list), f"{label} must be a list")
    return value


def require_string(value: object, label: str) -> str:
    require(isinstance(value, str) and value, f"{label} must be a non-empty string")
    return value


def validate_relative_path(value: object, label: str) -> str:
    require(
        isinstance(value, str) and value,
        f"{label} must be a non-empty relative path string",
    )
    require("\x00" not in value, f"{label} must not contain NUL")
    require("\\" not in value, f"{label} must not contain backslash: {value}")
    path = PurePosixPath(value)
    require(not path.is_absolute(), f"{label} must not be absolute: {value}")
    parts = path.parts
    require(
        parts and all(part not in ("", ".", "..") for part in parts),
        f"{label} contains traversal: {value}",
    )
    require(path.as_posix() == value, f"{label} is not a canonical relative path: {value}")
    return value


def validate_glob(value: object, label: str) -> str:
    require(isinstance(value, str) and value, f"{label} must be a non-empty string")
    require("\x00" not in value, f"{label} must not contain NUL")
    require("\\" not in value, f"{label} must not contain backslash: {value}")
    require(not value.startswith("/"), f"{label} must not be absolute: {value}")
    for part in PurePosixPath(value).parts:
        require(part != "..", f"{label} contains traversal: {value}")
    return value


def glob_matches(path: str, pattern: str) -> bool:
    if path == pattern:
        return True
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        if path == prefix or path.startswith(prefix + "/"):
            return True
    if pattern.startswith("**/"):
        suffix = pattern[3:]
        if "/" not in suffix:
            if path == suffix or path.endswith("/" + suffix):
                return True
        elif path.endswith(suffix) and (
            len(path) == len(suffix) or path[len(path) - len(suffix) - 1] == "/"
        ):
            return True
    try:
        if PurePosixPath(path).match(pattern):
            return True
    except (ValueError, TypeError):
        pass
    try:
        if fnmatch.fnmatchcase(path, pattern):
            return True
    except (ValueError, TypeError):
        pass
    return False


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sanitize_toolchain_env(value: object) -> str:
    if value is None or value == "not-set":
        return "not-set"
    if value == EXPECTED_TOOLCHAIN:
        return EXPECTED_TOOLCHAIN
    return "redacted-unexpected-value"


def read_confined_bytes(root: Path, relative: str, label: str) -> bytes:
    validate_relative_path(relative, f"{label} path")
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        try:
            status = current.lstat()
        except OSError as error:
            raise DryRunError(f"cannot read {label} {relative} (errno {getattr(error, 'errno', 'unknown')})") from error
        require(
            not stat.S_ISLNK(status.st_mode),
            f"{label} path contains a symlink component: {relative}",
        )
    require(stat.S_ISREG(status.st_mode), f"{label} must be a regular file: {relative}")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise DryRunError(f"{label} escapes the source root: {relative}") from error
    try:
        return current.read_bytes()
    except OSError as error:
        raise DryRunError(f"cannot read {label} {relative} (errno {getattr(error, 'errno', 'unknown')})") from error


def parse_json_object(data: bytes, label: str) -> dict:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DryRunError(f"{label} is not valid UTF-8: {error}") from error
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise DryRunError(f"invalid JSON in {label}: {error}") from error
    require(isinstance(value, dict), f"{label} must contain a JSON object")
    return value


def require_elf_x86_64(data: bytes, label: str) -> None:
    require(len(data) >= 64, f"{label} is too small to be an ELF executable")
    require(data[0:4] == b"\x7fELF", f"{label} is not an ELF executable")
    require(data[4] == 2, f"{label} is not a 64-bit (EI_CLASS) ELF object")
    require(data[5] == 1, f"{label} is not a little-endian (EI_DATA) ELF object")
    require(
        int.from_bytes(data[18:20], "little") == 62,
        f"{label} is not an x86-64 (e_machine) ELF object",
    )


def parse_cargo_package(text: str) -> tuple[str, str]:
    """Extract (name, version) from the [package] section without a TOML dependency."""
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
    return name, version


def check_gate(provenance: dict, inventory: dict) -> dict:
    """Independently re-check the blocked gate against exact canonical text."""
    require(
        inventory.get("schema") == EXPECTED_INVENTORY_SCHEMA,
        f"unexpected distribution inventory schema: {inventory.get('schema')!r}",
    )
    require_string(inventory.get("scope"), "distribution inventory scope")

    gate = require_object(inventory.get("rights_gate"), "rights_gate")
    require(gate.get("source") == EXPECTED_GATE_SOURCE, "rights_gate source changed")
    gate_decision = require_string(gate.get("publication_decision"), "rights_gate publication_decision")
    gate_notice = require_string(gate.get("notice_applicability"), "rights_gate notice_applicability")
    blocking_open = require_list(gate.get("blocking_open"), "rights_gate blocking_open")
    require(
        all(isinstance(item, str) and item for item in blocking_open),
        "rights_gate blocking_open must be a list of non-empty strings",
    )
    require(
        list(blocking_open) == list(EXPECTED_BLOCKING_OPEN),
        "rights_gate blocking_open changed; refusing to authorize against a moved gate",
    )
    require(gate.get("fail_closed") is True, "rights_gate fail_closed must be true")
    require_string(gate.get("rule"), "rights_gate rule")
    inventory_auth = require_object(
        gate.get("review_ci_branch_push_authorization"),
        "rights_gate review_ci_branch_push_authorization",
    )
    require(
        inventory_auth == EXPECTED_BRANCH_PUSH_AUTHORIZATION,
        "rights_gate review/CI branch-push authorization is not the exact canonical "
        "object; refusing dry-run against a moved authorization",
    )

    source_dist = require_object(inventory.get("source_distribution"), "source_distribution")
    require(
        source_dist.get("status") == "BLOCKED",
        "source distribution must remain BLOCKED; refusing dry-run against a moved gate",
    )
    require_string(source_dist.get("reason"), "source_distribution reason")

    binary = require_object(inventory.get("binary_distribution"), "binary_distribution")
    require(
        binary.get("status") == "BLOCKED",
        "binary distribution must remain BLOCKED; refusing dry-run against a moved gate",
    )
    require_string(binary.get("reason"), "binary_distribution reason")
    require(
        binary.get("target") == EXPECTED_TARGET,
        f"binary_distribution target changed: {binary.get('target')!r}",
    )

    members = require_list(binary.get("archive_members"), "binary_distribution archive_members")
    require(members, "binary_distribution archive_members must not be empty")
    member_pairs: list[tuple[str, str]] = []
    seen_sources: set[str] = set()
    seen_archives: set[str] = set()
    for index, member in enumerate(members):
        label = f"binary_distribution archive_members[{index}]"
        member = require_object(member, label)
        source = validate_relative_path(member.get("source"), f"{label} source")
        archive_path = validate_relative_path(member.get("archive_path"), f"{label} archive_path")
        require(member.get("required") is True, f"{label} required must be true")
        require(source not in seen_sources, f"{label} duplicate archive member source: {source}")
        require(
            archive_path not in seen_archives,
            f"{label} duplicate archive member archive_path: {archive_path}",
        )
        seen_sources.add(source)
        seen_archives.add(archive_path)
        member_pairs.append((source, archive_path))
    require(
        set(member_pairs) == set(EXPECTED_ARCHIVE_MEMBERS),
        "binary_distribution archive_members changed; only the explicit allowlist "
        f"{sorted(EXPECTED_ARCHIVE_MEMBERS)!r} may be archived",
    )
    require(
        len(member_pairs) == len(EXPECTED_ARCHIVE_MEMBERS),
        "binary_distribution archive_members must list exactly the allowlisted members",
    )
    require(
        set(archive for _, archive in member_pairs) == set(EXPECTED_ARCHIVE_PATHS),
        "archive allowlist changed; refusing to build from a moved allowlist",
    )

    generated = binary.get("generated_members")
    require(generated is not None, "binary_distribution generated_members is required")
    generated_list = require_list(generated, "binary_distribution generated_members")
    require(generated_list, "binary_distribution generated_members must not be empty")
    generated_pairs: list[tuple[str, str]] = []
    for index, member in enumerate(generated_list):
        label = f"binary_distribution generated_members[{index}]"
        member = require_object(member, label)
        archive_path = validate_relative_path(member.get("archive_path"), f"{label} archive_path")
        require(
            member.get("generator") == EXPECTED_BUILD_INFO_GENERATOR,
            f"{label} generator changed: {member.get('generator')!r}",
        )
        require(member.get("required") is True, f"{label} required must be true")
        generated_pairs.append((archive_path, str(member.get("generator"))))
    require(
        generated_pairs == list(EXPECTED_GENERATED_MEMBERS),
        "binary_distribution generated_members changed; expected the exact ordered "
        f"contract {list(EXPECTED_GENERATED_MEMBERS)!r}, got {generated_pairs!r}",
    )

    forbidden = require_list(binary.get("forbidden_globs"), "binary_distribution forbidden_globs")
    require(forbidden, "binary_distribution forbidden_globs must not be empty")
    forbidden_strings = [validate_glob(p, f"binary_distribution forbidden_globs[{i}]") for i, p in enumerate(forbidden)]
    require(
        len(set(forbidden_strings)) == len(forbidden_strings),
        "binary_distribution forbidden_globs contains duplicates",
    )
    for required_glob in sorted(REQUIRED_FORBIDDEN_GLOBS):
        require(
            required_glob in forbidden_strings,
            f"binary_distribution is missing required forbidden glob: {required_glob}",
        )

    fixture_paths = require_list(binary.get("fixture_paths"), "binary_distribution fixture_paths")
    require(fixture_paths, "binary_distribution fixture_paths must not be empty")
    fixture_strings = [
        validate_relative_path(p, f"binary_distribution fixture_paths[{i}]")
        for i, p in enumerate(fixture_paths)
    ]
    require(
        len(set(fixture_strings)) == len(fixture_strings),
        "binary_distribution fixture_paths contains duplicates",
    )

    all_archive_paths = [archive for _, archive in member_pairs] + sorted(EXPECTED_GENERATED_PATHS)
    require(
        sorted(all_archive_paths) == list(EXPECTED_ALL_ARCHIVE_PATHS),
        "combined archive member set changed; refusing to build from a moved allowlist",
    )
    for label, archive_path in [("archive member", p) for p in all_archive_paths]:
        for fixture in fixture_strings:
            require(
                archive_path != fixture,
                f"{label} {archive_path} allows a fixture into the release archive",
            )
        for pattern in forbidden_strings:
            require(
                not glob_matches(archive_path, pattern),
                f"{label} {archive_path} matches a forbidden glob into the release archive: "
                f"{pattern}",
            )
        require(
            archive_path not in EXPECTED_FIXTURE_PATHS,
            f"{label} {archive_path} is a fixture path",
        )
        require(
            "PROVENANCE.json" not in archive_path,
            f"{label} {archive_path} must never carry provenance inventory",
        )

    for index, (source, archive_path) in enumerate(member_pairs):
        label = f"binary_distribution archive_members[{index}]"
        for fixture in fixture_strings:
            require(
                source != fixture,
                f"{label} allows a fixture into the release archive: {fixture}",
            )
        for pattern in forbidden_strings:
            require(
                not glob_matches(source, pattern),
                f"{label} source matches a forbidden glob into the release archive: "
                f"{source} matches {pattern}",
            )

    rights = require_object(provenance.get("rights_review"), "rights_review")
    provenance_decision = require_string(rights.get("publication_decision"), "rights_review publication_decision")
    provenance_notice = require_string(rights.get("notice_applicability"), "rights_review notice_applicability")
    require(
        provenance_decision == EXPECTED_PUBLICATION_DECISION,
        "rights gate publication_decision is not the exact canonical blocked text; "
        "refusing dry-run against a moved gate (re-review required)",
    )
    require(
        provenance_notice == EXPECTED_NOTICE_APPLICABILITY,
        "NOTICE applicability must remain exactly UNRESOLVED",
    )
    require(
        gate_decision == provenance_decision,
        "inventory publication_decision does not match tests/fixtures/PROVENANCE.json",
    )
    provenance_auth = require_object(
        rights.get("review_ci_branch_push_authorization"),
        "rights_review review_ci_branch_push_authorization",
    )
    require(
        provenance_auth == EXPECTED_BRANCH_PUSH_AUTHORIZATION,
        "rights_review review/CI branch-push authorization is not the exact canonical "
        "object; refusing dry-run against a moved authorization",
    )
    require(
        inventory_auth == provenance_auth,
        "inventory review/CI branch-push authorization does not match "
        "tests/fixtures/PROVENANCE.json",
    )
    require(
        gate_notice == provenance_notice,
        "inventory notice_applicability does not match tests/fixtures/PROVENANCE.json",
    )
    require(
        rights.get("rights_holder_authority") == ATTESTED_RIGHTS,
        "rights status must remain honest (owner-attested, not independently verified)",
    )
    attestation = require_object(rights.get("owner_attestation"), "rights_review owner_attestation")
    require(
        attestation.get("status") == ATTESTED_RIGHTS,
        "owner attestation status must remain honest",
    )
    require(
        attestation.get("independent_verification") is False,
        "owner attestation must not be represented as independent verification",
    )

    checklist = require_object(rights.get("notice_checklist"), "rights_review notice_checklist")
    require(
        checklist.get("status") == EXPECTED_CHECKLIST_STATUS,
        "notice checklist status is not the exact canonical blocked text; "
        "refusing dry-run against a moved gate",
    )
    require_string(checklist.get("scope"), "rights_review notice_checklist scope")
    items = require_list(checklist.get("items"), "notice_checklist items")
    require(items, "notice_checklist items must not be empty")
    by_id: dict[str, dict] = {}
    for index, item in enumerate(items):
        item = require_object(item, f"notice_checklist items[{index}]")
        item_id = require_string(item.get("id"), f"notice_checklist items[{index}] id")
        require(item_id not in by_id, f"notice_checklist contains duplicate id: {item_id}")
        by_id[item_id] = item
    require("RIGHTS-01" in by_id, "rights gate is missing checklist item: RIGHTS-01")
    require(
        by_id["RIGHTS-01"].get("blocking") is True,
        "rights gate item is not blocking: RIGHTS-01",
    )
    for expected_id, expected in EXPECTED_BLOCKING_ITEMS.items():
        require(expected_id in by_id, f"rights gate is missing blocking item: {expected_id}")
        entry = by_id[expected_id]
        require(
            entry.get("blocking") is True,
            f"rights gate item is not blocking: {expected_id}",
        )
        require(
            entry.get("status") == "OPEN",
            f"rights gate blocking item is not OPEN: {expected_id}",
        )
        require(
            entry.get("action") == expected["action"],
            f"rights gate item action changed: {expected_id}; refusing against a moved gate",
        )
        require(
            entry.get("owner") == expected["owner"],
            f"rights gate item owner changed: {expected_id}; refusing against a moved gate",
        )
        require(
            entry.get("evidence") == expected["evidence"],
            f"rights gate item evidence changed: {expected_id}; refusing against a moved gate",
        )
    open_blocking = sorted(
        item_id
        for item_id, entry in by_id.items()
        if entry.get("blocking") is True and entry.get("status") == "OPEN"
    )
    require(
        set(open_blocking) == EXPECTED_BLOCKING_OPEN_SET,
        "rights gate blocking-open set changed; refusing dry-run (re-review required)",
    )
    require(
        set(blocking_open) == set(open_blocking),
        "inventory blocking_open does not match the open blocking items in PROVENANCE.json",
    )

    provenance_fixtures = require_list(provenance.get("fixtures"), "provenance fixtures")
    require(provenance_fixtures, "provenance fixtures must not be empty")
    provenance_paths = [
        validate_relative_path(
            require_object(e, f"provenance fixtures[{i}]").get("path"),
            f"provenance fixtures[{i}] path",
        )
        for i, e in enumerate(provenance_fixtures)
    ]
    require(
        set(provenance_paths) == EXPECTED_FIXTURE_PATHS,
        "fixture set in PROVENANCE.json changed; refusing against a moved gate",
    )
    require(
        set(fixture_strings) == set(provenance_paths),
        "inventory fixture_paths do not match the fixture set in tests/fixtures/PROVENANCE.json",
    )
    for index, entry in enumerate(provenance_fixtures):
        entry = require_object(entry, f"provenance fixtures[{index}]")
        require(
            "release_archive_member" in entry,
            f"provenance fixtures[{index}] must declare release_archive_member",
        )
        require(
            entry.get("release_archive_member") is False,
            f"provenance fixtures[{index}] must not be a release archive member",
        )

    return {
        "publication_decision": provenance_decision,
        "notice_applicability": provenance_notice,
        "blocking_open": list(EXPECTED_BLOCKING_OPEN),
        "source_status": "BLOCKED",
        "binary_status": "BLOCKED",
        "target": EXPECTED_TARGET,
        "archive_members": sorted(member_pairs),
        "generated_members": sorted(EXPECTED_GENERATED_MEMBERS),
        "all_archive_members": list(EXPECTED_ALL_ARCHIVE_PATHS),
        "review_ci_branch_push_authorization": dict(EXPECTED_BRANCH_PUSH_AUTHORIZATION),
        "forbidden_globs": sorted(forbidden_strings),
        "fixture_paths": sorted(fixture_strings),
        "provenance_path": PROVENANCE_REL,
        "inventory_path": INVENTORY_REL,
    }


def git_identity(source_root: Path, field: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", field],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return "unavailable"
    value = (completed.stdout or "").strip()
    if completed.returncode != 0 or not value:
        return "unavailable"
    return value


def git_command(source_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(source_root), *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def git_source_date(source_root: Path) -> str:
    """Deterministic source date: the commit timestamp, never the wall clock."""
    try:
        completed = git_command(source_root, "show", "-s", "--format=%cI", "HEAD")
    except (OSError, ValueError, subprocess.SubprocessError):
        return "unavailable"
    value = (completed.stdout or "").strip()
    if completed.returncode != 0 or not value or "\n" in value:
        return "unavailable"
    try:
        return datetime.datetime.fromisoformat(value).astimezone(datetime.timezone.utc).isoformat(timespec="seconds")
    except ValueError:
        return "unavailable"


def _capture_version_bytes(argv: list[str], timeout: float = 30) -> bytes | None:
    """Capture version-tool stdout bytes with a true hard bound, fail closed.

    Uses `Popen(stdout=PIPE, stderr=DEVNULL)` and reads at most
    `MAX_TOOLCHAIN_OUTPUT_BYTES + 1` bytes. Stderr is never buffered, so a
    stderr flood cannot block or fill memory. The child is killed as soon as
    oversize output is observed, and every wait is bounded by `timeout`, so a
    hung or silent toolchain cannot deadlock the builder. Returns None on
    spawn errors, timeout, non-zero exit, empty output, oversized output, or
    any read error; oversized bytes are discarded and never returned.
    Non-finite timeouts are rejected rather than used in select/wait
    arithmetic.
    """
    try:
        timeout_value = float(timeout)
    except (TypeError, ValueError):
        timeout_value = 30.0
    if not math.isfinite(timeout_value):
        return None
    if timeout_value <= 0:
        timeout_value = 30.0
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    stdout = proc.stdout
    if stdout is None:
        try:
            proc.kill()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
        return None
    try:
        try:
            fd = stdout.fileno()
        except (OSError, ValueError, AttributeError):
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
            return None
        try:
            os.set_blocking(fd, False)
        except (OSError, ValueError, AttributeError):
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
            return None
        data = bytearray()
        limit = MAX_TOOLCHAIN_OUTPUT_BYTES + 1
        deadline = time.monotonic() + timeout_value
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                return None
            try:
                rlist, _, _ = select.select([stdout], [], [], remaining)
            except InterruptedError:
                continue
            except (OSError, ValueError):
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                return None
            if not rlist:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                return None
            to_read = limit - len(data)
            if to_read <= 0:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                return None
            try:
                chunk = os.read(fd, to_read)
            except InterruptedError:
                continue
            except BlockingIOError:
                if proc.poll() is not None:
                    continue
                continue
            except OSError:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                return None
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_TOOLCHAIN_OUTPUT_BYTES:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
            return None
        try:
            returncode = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
            return None
        except (OSError, ValueError):
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
            return None
        if returncode != 0:
            return None
        if not data:
            return None
        if len(data) > MAX_TOOLCHAIN_OUTPUT_BYTES:
            return None
        return bytes(data)
    finally:
        try:
            stdout.close()
        except Exception:
            pass
        try:
            if proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
        except Exception:
            pass


def _normalize_rustc_output(raw: bytes) -> str | None:
    """Strictly validate raw `rustc --version` bytes.

    Accepts only the complete official line, with at most one optional
    trailing LF or CRLF. Returns the canonical line without trailing newline
    on success, else None. Never returns attacker-controlled content.
    """
    if len(raw) > MAX_TOOLCHAIN_OUTPUT_BYTES:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if _RUSTC_VERSION_LINE_RE.fullmatch(text) is None:
        return None
    return EXPECTED_RUSTC_VERSION_LINE


def _normalize_cargo_output(raw: bytes) -> str | None:
    """Strictly validate raw `cargo --version` bytes (same rules as rustc)."""
    if len(raw) > MAX_TOOLCHAIN_OUTPUT_BYTES:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if _CARGO_VERSION_LINE_RE.fullmatch(text) is None:
        return None
    return EXPECTED_CARGO_VERSION_LINE


def observed_toolchain(timeout: float = 30) -> str:
    raw = _capture_version_bytes(["rustc", "--version"], timeout=timeout)
    if raw is None:
        return "not-observed"
    normalized = _normalize_rustc_output(raw)
    return normalized if normalized is not None else "not-observed"


def observed_cargo_version(timeout: float = 30) -> str:
    raw = _capture_version_bytes(["cargo", "--version"], timeout=timeout)
    if raw is None:
        return "not-observed"
    normalized = _normalize_cargo_output(raw)
    return normalized if normalized is not None else "not-observed"


def git_member_status(source_root: Path, relative: str) -> str | None:
    """Return 'clean', 'dirty:…', or 'untracked…' for one member.

    Only the known build output target/release/astatine may be an
    untracked build artifact; any other untracked member is reported as
    'untracked:<path>' and fails verification. Returns None when the
    source root is not a git repository (or git cannot answer), in which
    case the caller records an unverified skip.
    """
    if git_identity(source_root, "HEAD") == "unavailable":
        return None
    try:
        tracked = git_command(source_root, "ls-files", "--error-unmatch", "--", relative)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if tracked.returncode != 0:
        if relative == BINARY_SOURCE:
            return "untracked-build-artifact"
        return f"untracked:{relative}"
    try:
        diff = git_command(source_root, "diff", "--quiet", "HEAD", "--", relative)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if diff.returncode == 0:
        return "clean"
    if diff.returncode == 1:
        return f"dirty:{relative}"
    return None


def verify_git_clean(resolved_root: Path, member_sources: list[str]) -> tuple[bool, dict[str, str]]:
    """Fail on a dirty or unexpected-untracked archive member."""
    statuses: dict[str, str] = {}
    unknown: list[str] = []
    for source in member_sources:
        status = git_member_status(resolved_root, source)
        if status is None:
            unknown.append(source)
        else:
            statuses[source] = status
    if unknown:
        return False, {
            "note": "fails closed: source root is not a Git checkout "
            "(or git is unavailable); no clean-tree record is produced"
        }
    dirty = sorted(source for source, status in statuses.items() if status.startswith("dirty:"))
    untracked = sorted(
        source
        for source, status in statuses.items()
        if status.startswith("untracked:") and source != BINARY_SOURCE
    )
    require(
        not dirty,
        "archive member differs from committed HEAD state "
        f"(commit the change or restore the file): {dirty}",
    )
    require(
        not untracked,
        "archive member is not tracked by git "
        f"(tracked documents must be committed and clean): {untracked}",
    )
    return True, statuses


def verify_source_clean(resolved_root: Path) -> tuple[bool, dict[str, object]]:
    """Require the full source tree clean at HEAD, including both gate files.

    Rejects tracked changes (staged and unstaged) and non-ignored untracked
    files. Git-ignored files generally are not inspected by this Git check;
    target/ is the expected build output and the only explicitly allowed
    untracked path. Returns (verified, status) with gate-file cleanliness
    recorded.
    """
    if git_identity(resolved_root, "HEAD") == "unavailable":
        return False, {
            "note": "fails closed: source root is not a Git checkout "
            "(or git is unavailable); no clean-tree record is produced"
        }
    try:
        status = git_command(resolved_root, "status", "--porcelain", "--untracked-files=all")
        worktree = git_command(resolved_root, "diff", "--quiet", "HEAD")
        staged = git_command(resolved_root, "diff", "--cached", "--quiet", "HEAD")
    except (OSError, ValueError, subprocess.SubprocessError):
        raise DryRunError("cannot verify source cleanliness; refusing dry-run without a clean tree") from None
    require(status.returncode == 0, "git status failed; refusing dry-run without a clean tree")
    for label, completed in (("git diff HEAD", worktree), ("git diff --cached HEAD", staged)):
        require(
            completed.returncode in (0, 1),
            f"{label} failed; refusing dry-run without a clean tree",
        )
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
    require(
        not dirty,
        "source tree is not clean at HEAD (commit, restore, or remove the change; "
        "Git-ignored files are not inspected by this check and target/ is the "
        "expected build output and the only explicitly allowed untracked path): "
        + "; ".join(dirty[:10]),
    )
    gate_clean: dict[str, bool] = {}
    for gate_file in (PROVENANCE_REL, INVENTORY_REL):
        try:
            work = git_command(resolved_root, "diff", "--quiet", "HEAD", "--", gate_file)
            stag = git_command(resolved_root, "diff", "--cached", "--quiet", "HEAD", "--", gate_file)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            raise DryRunError("cannot verify gate-file cleanliness; refusing dry-run without a clean tree") from None
        gate_clean[gate_file] = work.returncode == 0 and stag.returncode == 0
    require(
        all(gate_clean.values()),
        f"gate files are not clean at HEAD: {sorted(k for k, v in gate_clean.items() if not v)}",
    )
    return True, {
        "gate_files_clean": gate_clean,
        "allowed_untracked_build_output": sorted(set(allowed_untracked)),
    }


def generate_build_info(
    *,
    package_name: str,
    package_version: str,
    repository: str,
    commit: str,
    tree: str,
    source_date: str,
    cargo_lock_sha256: str,
    observed_rustc: str,
    observed_cargo: str,
    gate: dict,
) -> bytes:
    """Deterministic machine-readable build record; no wall-clock timestamps."""
    how_to_obtain = f"git clone https://github.com/{repository}.git && git checkout {commit}"
    record = {
        "schema": BUILD_INFO_SCHEMA,
        "distribution": BUILD_INFO_DISTRIBUTION,
        "publication_authorized": False,
        "package": {"name": package_name, "version": package_version, "binary": EXPECTED_BINARY_NAME},
        "target": EXPECTED_TARGET,
        "profile": EXPECTED_BUILD_PROFILE,
        "source": {
            "repository": repository,
            "commit": commit,
            "tree": tree,
            "source_date_utc": source_date,
            "source_root_included": False,
        },
        "build": {
            "command": EXPECTED_CARGO_COMMAND,
            "command_is_documented": True,
            "verified_by_this_script": False,
            "rustc_version": observed_rustc,
            "cargo_version": observed_cargo,
            "cargo_lock_sha256": cargo_lock_sha256,
        },
        "corresponding_source": {
            "repository": repository,
            "commit": commit,
            "tree": tree,
            "included_in_archive": False,
            "how_to_obtain": how_to_obtain,
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
        "build_linkage": BINARY_BUILD_LINKAGE_NOTE,
        "rights_gate": {
            "publication_decision": gate["publication_decision"],
            "notice_applicability": gate["notice_applicability"],
            "blocking_open": list(gate["blocking_open"]),
            "review_ci_branch_push_authorization": dict(
                gate["review_ci_branch_push_authorization"]
            ),
        },
    }
    return (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")


def generate_install_md(
    *,
    package_name: str,
    package_version: str,
    repository: str,
    commit: str,
    tree: str,
    source_date: str,
    cargo_lock_sha256: str,
) -> bytes:
    """Deterministic human-readable install/upgrade notes; no wall-clock timestamps."""
    how_to_obtain = f"git clone https://github.com/{repository}.git && git checkout {commit}"
    text = f"""# Astatine miner {package_version} — Linux x86_64 dry-run install notes

NOT FOR PUBLICATION OR DISTRIBUTION. Dry-run only. The rights gate is
BLOCKED, and this archive authenticates no publisher and no legal approval.
See BUILD-INFO.json for the machine-readable record and
release-provenance.json (kept outside this archive) for the dry-run evidence.

- Package: {package_name}
- Binary: {EXPECTED_BINARY_NAME}
- Version: {package_version}
- Target: {EXPECTED_TARGET}
- Profile: {EXPECTED_BUILD_PROFILE}

## Exact source identity

- Repository: {repository}
- Commit: {commit}
- Tree: {tree}
- Source date (commit timestamp): {source_date}
- The corresponding source tree is NOT inside this archive.

## Install

1. Verify the archive against the external SHA256SUMS file distributed
   alongside it (never trust the archive alone):
   `sha256sum -c SHA256SUMS`
2. Extract: `tar -xzf {ARTIFACT_FILENAME}`
3. Install the `astatine` binary with mode 0755 onto your PATH, for example:
   `install -m 0755 astatine /usr/local/bin/astatine`
4. Confirm: `astatine --version` (expect {package_version}).

## Upgrade (preserve user state)

1. Stop the running miner first.
2. Keep your existing configuration, wallets, keystores, credentials, and
   transaction journals exactly where they are. Default state locations:
   - Linux: `${{XDG_CONFIG_HOME:-$HOME/.config}}/astatine`
   - macOS: `~/Library/Application Support/Astatine`
   - Windows: `%APPDATA%\\Astatine`
   See the corresponding source README for custom state locations.
3. Replace ONLY the `astatine` binary. Never overwrite, delete,
   reinitialize, or migrate state files to satisfy a new binary.
4. Downgrade compatibility is not guaranteed; keep a recoverable copy of
   your prior binary and state before upgrading.

## Corresponding source and dependencies

- Obtain the exact corresponding source (not included here):
  `{how_to_obtain}`
- Dependency pins: {CARGO_LOCK_REL} SHA-256 `{cargo_lock_sha256}`.
- Third-party notices: THIRD_PARTY_LICENSES.md (in this archive).
- License: LICENSE-MIT (in this archive).

## Build linkage

{BINARY_BUILD_LINKAGE_NOTE}
"""
    return text.encode("utf-8")


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
    # Resolve first and create only the resolved path. This both checks
    # containment before any mkdir and prevents `..`/alias paths from creating
    # intermediate directories inside the source tree.
    candidate = output_dir.resolve(strict=False)
    try:
        candidate.relative_to(resolved_root)
        raise DryRunError("--output-dir must lie outside the source tree")
    except ValueError:
        pass
    try:
        original = os.lstat(output_dir)
    except FileNotFoundError:
        original = None
    except OSError as error:
        raise DryRunError(f"cannot inspect --output-dir (errno {getattr(error, 'errno', 'unknown')})") from error
    if original is not None:
        require(
            not stat.S_ISLNK(original.st_mode),
            "--output-dir must not be a symlink",
        )
    try:
        existing = os.lstat(candidate)
    except FileNotFoundError:
        existing = None
    except OSError as error:
        raise DryRunError(f"cannot inspect --output-dir (errno {getattr(error, 'errno', 'unknown')})") from error
    if existing is not None:
        require(
            stat.S_ISDIR(existing.st_mode),
            "--output-dir exists and is not a directory",
        )
        try:
            entries = sorted(os.listdir(candidate))
        except OSError as error:
            raise DryRunError(f"cannot inspect --output-dir (errno {getattr(error, 'errno', 'unknown')})") from error
        require(
            entries == [],
            "--output-dir must be new or empty; refusing to write into a non-empty directory",
        )
    else:
        try:
            candidate.mkdir(parents=True, exist_ok=False)
        except OSError as error:
            raise DryRunError(f"cannot create --output-dir (errno {getattr(error, 'errno', 'unknown')})") from error
    try:
        resolved_out = candidate.resolve(strict=True)
    except OSError as error:
        raise DryRunError(f"--output-dir is not readable (errno {getattr(error, 'errno', 'unknown')})") from error
    try:
        resolved_out.relative_to(resolved_root)
        raise DryRunError("--output-dir must lie outside the source tree")
    except ValueError:
        pass
    require(
        resolved_out.is_dir() and not resolved_out.is_symlink(),
        "--output-dir must be a real directory outside the source tree",
    )
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
        raise DryRunError(f"refusing to overwrite existing output file: {name}") from None
    except OSError as error:
        raise DryRunError(f"cannot write {name} (errno {getattr(error, 'errno', 'unknown')})") from error
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except OSError as error:
        raise DryRunError(f"cannot write {name} (errno {getattr(error, 'errno', 'unknown')})") from error
    return path


def run(
    source_root: Path,
    output_dir: Path,
    mode: str = "dry-run",
) -> dict:
    require(mode in ("dry-run", "release"), f"unknown mode: {mode!r}")
    require(
        mode != "release",
        "release mode is not authorized: no authorized publisher exists; "
        "use --mode dry-run for the blocked-gate rehearsal only",
    )
    try:
        resolved_root = source_root.resolve(strict=False)
    except (OSError, ValueError, RuntimeError):
        raise DryRunError("source root is not readable; refusing dry-run") from None
    require(resolved_root.is_dir(), "source root is not a directory")
    try:
        resolved_root = resolved_root.resolve(strict=True)
    except (OSError, ValueError, RuntimeError) as error:
        raise DryRunError(f"source root is not readable (errno {getattr(error, 'errno', 'unknown')})") from None

    # Canonical gate paths only: no overrides exist, so a caller cannot
    # substitute an old blocked copy after the real gate changes.
    provenance_bytes = read_confined_bytes(resolved_root, PROVENANCE_REL, "fixture provenance")
    provenance = parse_json_object(provenance_bytes, PROVENANCE_REL)
    inventory_bytes = read_confined_bytes(resolved_root, INVENTORY_REL, "distribution inventory")
    inventory = parse_json_object(inventory_bytes, INVENTORY_REL)
    gate = check_gate(provenance, inventory)

    observed = observed_toolchain()
    require(
        observed == EXPECTED_RUSTC_VERSION_LINE,
        "observed toolchain is not the pinned Rust 1.94.1 exact version line",
    )
    cargo_version = observed_cargo_version()
    require(
        cargo_version == EXPECTED_CARGO_VERSION_LINE,
        "observed cargo is not the pinned Cargo 1.94.1 exact version line",
    )
    lock_bytes = read_confined_bytes(resolved_root, CARGO_LOCK_REL, "cargo lockfile")
    lock_sha = sha256_hex(lock_bytes)
    cargo_text = read_confined_bytes(resolved_root, CARGO_TOML_REL, "cargo manifest").decode("utf-8")
    package_name, package_version = parse_cargo_package(cargo_text)
    repository = read_confined_bytes(resolved_root, REPOSITORY_REL, "release repository").decode("utf-8").strip()
    require(
        repository == EXPECTED_REPOSITORY,
        f"release repository changed: {repository!r}",
    )

    member_inputs: list[tuple[str, bytes, int]] = []
    member_records: list[dict] = []
    for source, archive_path in gate["archive_members"]:
        data = read_confined_bytes(resolved_root, source, f"archive member {archive_path}")
        if archive_path == "astatine":
            require_elf_x86_64(data, f"archive member {archive_path} ({source})")
        mode_bits = FILE_MODE_BIN if archive_path == "astatine" else FILE_MODE_DOC
        member_inputs.append((archive_path, data, mode_bits))
        member_records.append(
            {
                "archive_path": archive_path,
                "source": source,
                "generated": False,
                "sha256": sha256_hex(data),
                "bytes": len(data),
                "mode": oct(mode_bits),
            }
        )

    source_verified, source_status = verify_source_clean(resolved_root)
    require(
        source_verified,
        "source root is not a verifiably clean Git checkout at HEAD "
        "(non-Git roots fail closed and produce no clean-tree record); "
        "refusing dry-run",
    )
    git_verified, git_status = verify_git_clean(
        resolved_root, [source for source, _ in gate["archive_members"]]
    )
    require(
        git_verified,
        "archive members are not verifiably clean at HEAD; refusing dry-run",
    )

    commit = git_identity(resolved_root, "HEAD")
    tree = git_identity(resolved_root, "HEAD^{tree}")
    source_date = git_source_date(resolved_root)
    require(commit != "unavailable", "commit identity is unavailable")
    require(tree != "unavailable", "tree identity is unavailable")
    require(source_date != "unavailable", "commit source date is unavailable")

    generated_members = [
        (
            "BUILD-INFO.json",
            generate_build_info(
                package_name=package_name,
                package_version=package_version,
                repository=repository,
                commit=commit,
                tree=tree,
                source_date=source_date,
                cargo_lock_sha256=lock_sha,
                observed_rustc=observed,
                observed_cargo=cargo_version,
                gate=gate,
            ),
            FILE_MODE_DOC,
        ),
        (
            "INSTALL.md",
            generate_install_md(
                package_name=package_name,
                package_version=package_version,
                repository=repository,
                commit=commit,
                tree=tree,
                source_date=source_date,
                cargo_lock_sha256=lock_sha,
            ),
            FILE_MODE_DOC,
        ),
    ]
    for archive_path, data, mode_bits in generated_members:
        require(
            archive_path in EXPECTED_GENERATED_PATHS,
            f"refusing to generate unexpected archive member: {archive_path}",
        )
        member_inputs.append((archive_path, data, mode_bits))
        member_records.append(
            {
                "archive_path": archive_path,
                "source": f"generated:{archive_path}",
                "generated": True,
                "generator": EXPECTED_BUILD_INFO_GENERATOR,
                "sha256": sha256_hex(data),
                "bytes": len(data),
                "mode": oct(mode_bits),
            }
        )
    member_records.sort(key=lambda item: item["archive_path"])
    require(
        [item["archive_path"] for item in member_records] == list(EXPECTED_ALL_ARCHIVE_PATHS),
        "archive member set changed; refusing to build",
    )

    artifact_bytes = build_deterministic_tarball(member_inputs)
    artifact_sha = sha256_hex(artifact_bytes)

    resolved_out = prepare_output_dir(output_dir, resolved_root)
    artifact_path = write_exclusive(resolved_out, ARTIFACT_FILENAME, artifact_bytes)
    checksums_path = write_exclusive(
        resolved_out, "SHA256SUMS", f"{artifact_sha}  {ARTIFACT_FILENAME}\n".encode("utf-8")
    )

    record = {
        "schema": "astatine-release-dry-run-provenance/v1",
        "mode": "dry-run",
        "provenance_path": PROVENANCE_REL,
        "inventory_path": INVENTORY_REL,
        "package_name": package_name,
        "package_version": package_version,
        "binary_name": EXPECTED_BINARY_NAME,
        "build_profile": EXPECTED_BUILD_PROFILE,
        "target": EXPECTED_TARGET,
        "distribution_target": EXPECTED_TARGET,
        "cargo_command": EXPECTED_CARGO_COMMAND,
        "cargo_lock_sha256": lock_sha,
        "observed_cargo_version": cargo_version,
        "binary_install": {
            "source": BINARY_SOURCE,
            "archive_path": EXPECTED_BINARY_NAME,
            "mode": oct(FILE_MODE_BIN),
            "placement": "archive root",
            "note": "scope is the astatine native binary only; not an npm package",
        },
        "pinned_toolchain": EXPECTED_TOOLCHAIN,
        "observed_toolchain": observed,
        "observed_rustc_version": observed,
        "rustup_toolchain_env": sanitize_toolchain_env(os.environ.get("RUSTUP_TOOLCHAIN", "not-set")),
        "commit": commit,
        "tree": tree,
        "source_date": source_date,
        "repository": repository,
        "git_verified": git_verified,
        "git_status": git_status,
        "source_clean_at_head": source_verified,
        "source_clean_status": source_status,
        "binary_build_linkage": BINARY_BUILD_LINKAGE_NOTE,
        "documented_build_pipeline": [
            "python3 -B support/verify-fixture-provenance.py",
            "python3 -B support/verify-distribution-inventory.py",
            "cargo build --locked --release",
            "target/release/astatine --version",
            "target/release/astatine --help",
            "python3 -B support/release/build-dry-run.py --mode dry-run --output-dir <new-empty-dir-outside-source-tree>",
        ],
        "artifact": {
            "filename": ARTIFACT_FILENAME,
            "sha256": artifact_sha,
            "bytes": len(artifact_bytes),
            "members": member_records,
        },
        "gate": gate,
        "publication_authorized": False,
        "required_hosted_ci": {
            "requirement": "green Rust CI for the exact dispatched commit",
            "verified_by_this_script": False,
            "status": "required-not-verified",
            "note": "Inspect hosted workflow results for the exact commit; dry-run success does not imply CI success and does not satisfy E-06.",
        },
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "notes": (
            "Dry-run only: no publication, upload, release asset, tag, release, "
            "attestation dispatch, or external release-binary signing was "
            "performed by this script or the dry-run workflow. No transparency-log "
            "entry is created. This record contains no absolute checkout path, "
            "no raw invocation, and no verbatim environment path; "
            "rustup_toolchain_env is sanitized to the pinned value, not-set, "
            "or redacted. Legitimate provenance "
            "(commit, tree, source date, toolchain, lock hash, artifact and "
            "member hashes, gate state) is preserved. Reproducibility "
            "bit-for-bit across hosts is not claimed."
        ),
    }
    record_path = write_exclusive(
        resolved_out, "release-provenance.json", (json.dumps(record, indent=2) + "\n").encode("utf-8")
    )

    return {
        "artifact_path": str(artifact_path),
        "artifact_sha256": artifact_sha,
        "artifact_bytes": len(artifact_bytes),
        "members": [item["archive_path"] for item in member_records],
        "member_hashes": {item["archive_path"]: item["sha256"] for item in member_records},
        "publication_authorized": False,
        "publication_decision": gate["publication_decision"],
        "notice_applicability": gate["notice_applicability"],
        "blocking_open": gate["blocking_open"],
        "git_verified": git_verified,
        "source_clean_at_head": source_verified,
        "provenance_path": str(record_path),
        "cargo_lock_sha256": lock_sha,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline blocked-gate Linux release dry-run builder.")
    parser.add_argument("--mode", choices=("dry-run", "release"), default="dry-run")
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = run(
            source_root=args.source_root,
            output_dir=args.output_dir,
            mode=args.mode,
        )
    except DryRunError as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}, indent=2), file=sys.stderr)
        return 1
    except OSError as error:
        print(json.dumps({"status": "FAIL", "error": f"filesystem error (errno {getattr(error, 'errno', 'unknown')})"}, indent=2), file=sys.stderr)
        return 1
    public_result = {
        "status": "PASS",
        "artifact_filename": ARTIFACT_FILENAME,
        "artifact_sha256": result["artifact_sha256"],
        "artifact_bytes": result["artifact_bytes"],
        "members": result["members"],
        "member_hashes": result["member_hashes"],
        "publication_authorized": result["publication_authorized"],
        "publication_decision": result["publication_decision"],
        "notice_applicability": result["notice_applicability"],
        "blocking_open": result["blocking_open"],
        "git_verified": result["git_verified"],
        "source_clean_at_head": result["source_clean_at_head"],
        "cargo_lock_sha256": result["cargo_lock_sha256"],
        "provenance_file": "release-provenance.json",
        "checksums_file": "SHA256SUMS",
        "note": "absolute filesystem paths are withheld from stdout; open the files in the requested --output-dir",
    }
    print(json.dumps(public_result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
