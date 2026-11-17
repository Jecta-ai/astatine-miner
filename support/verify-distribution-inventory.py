#!/usr/bin/env python3
"""Offline fail-closed verifier for support/release/distribution-inventory.json.

The original blocked-v1 checks are retained unchanged. Schema v3 dispatches to
support/release/gate.py and requires the substantive release-intent evidence
(owner-authorized release intent with cited technical NOTICE review,
license/notice artifacts and hashes, DONE checklist, pinned allowlists/targets,
and draft-only release controls with final controls outstanding). Performs no
network, build, wallet, or publication operation and never claims a release
archive exists.

A PASS only confirms the recorded release-intent state is truthful. It does NOT
authorize final publication, claim a legal conclusion, or assert a separate
approval; v3 records owner-authorized intent with final release controls
outstanding and remains draft-only with owner manual publication after admin
immutable-setting verification. Moving between states requires reviewed code
changes, not data-only edits to the JSON files.

Usage:
    python3 -B support/verify-distribution-inventory.py [root]

Exit status is 0 on PASS and 1 on any failure. PASS details go to stdout and
FAIL details go to stderr, both as JSON.
"""

from __future__ import annotations

import argparse
import fnmatch
import importlib.util
import json
import stat
import sys
from pathlib import Path, PurePosixPath

INVENTORY_REL = "support/release/distribution-inventory.json"
PROVENANCE_REL = "tests/fixtures/PROVENANCE.json"
EXPECTED_SCHEMA = "astatine-distribution-inventory/v1"
EXPECTED_GATE_SOURCE = "tests/fixtures/PROVENANCE.json"
EXPECTED_BLOCKING_OPEN = ["RIGHTS-02", "RIGHTS-03", "RIGHTS-04", "RIGHTS-05"]
EXPECTED_BLOCKING_OPEN_SET = frozenset(EXPECTED_BLOCKING_OPEN)
EXPECTED_TARGET = "x86_64-unknown-linux-gnu"
EXPECTED_ARCHIVE_MEMBERS = (
    ("target/release/astatine", "astatine"),
    ("LICENSE-MIT", "LICENSE-MIT"),
    ("THIRD_PARTY_LICENSES.md", "THIRD_PARTY_LICENSES.md"),
)
EXPECTED_GENERATOR = "support/release/build-dry-run.py"
# Ordered generated (in-memory) archive members: source/install/dependency
# metadata only. They must not contain fixtures or imply publication.
EXPECTED_GENERATED_MEMBERS = (
    ("BUILD-INFO.json", EXPECTED_GENERATOR),
    ("INSTALL.md", EXPECTED_GENERATOR),
)
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
EXPECTED_PUBLICATION_DECISION = (
    "BLOCKED pending review of rights and notice applicability; "
    "first-party ownership is owner-attested and not independently verified."
)
EXPECTED_NOTICE_APPLICABILITY = "UNRESOLVED"
EXPECTED_CHECKLIST_STATUS = "OPEN \u2014 publication remains BLOCKED"
# Project-owner limited authorization: review/CI branch push only. Kept in
# this file so the distribution verifier stands independent of the fixture
# verifier. It changes no BLOCKED/OPEN status.
EXPECTED_REVIEW_PUSH_AUTH = {
    "status": "AUTHORIZED \u2014 REVIEW/CI ONLY",
    "authorized_by": "project owner",
    "authorized_on": "2026-11-16",
    "scope": (
        "Push the fix/phase-e-e02-e07 remediation branch to the already-public "
        "repository solely for review and CI."
    ),
    "public_repository_visibility": (
        "The repository is already public. That visibility does not authorize a "
        "source archive, binary archive or release, tag or release publication, "
        "or workflow attestation dispatch."
    ),
    "not_authorized": [
        "source archive distribution",
        "binary archive or release distribution",
        "tag or public release publication",
        "workflow attestation dispatch",
        "broader license grant or legal clearance",
        "resolution of RIGHTS-02 through RIGHTS-05",
    ],
    "rights_gate_unchanged": (
        "RIGHTS-02 through RIGHTS-05 remain OPEN and blocking; "
        "source_distribution and binary_distribution remain BLOCKED."
    ),
}
# Pinned canonical notice-checklist entries for the blocking items. A reworded
# action, owner, or evidence string must fail; no legal approval is inferred.
EXPECTED_BLOCKER_DETAILS = {
    "RIGHTS-02": {
        "action": (
            "Decide whether Apache-2.0 NOTICE propagation applies to each "
            "distributed artifact. The contract fixtures are not "
            "release-archive members, so any obligation follows source "
            "redistribution of the fixtures rather than the miner binary."
        ),
        "owner": "project owner and release approver",
        "evidence": (
            "rights_review.copyright_evidence; fixtures FIX-01 and FIX-02 "
            "both set release_archive_member to false."
        ),
    },
    "RIGHTS-03": {
        "action": (
            "If the two first-party contract fixtures remain in the public "
            "source tree, add the Apache-2.0 license text and a copyright "
            "statement for them, or remove those fixtures from the public tree."
        ),
        "owner": "project owner",
        "evidence": (
            "tests/fixtures ships OPENZEPPELIN_LICENSE.txt only; no "
            "Apache-2.0 license text accompanies FIX-01 or FIX-02."
        ),
    },
    "RIGHTS-04": {
        "action": (
            "Confirm authorship and redistribution authority for MockAST and "
            "keep the OpenZeppelin MIT notice with any redistribution of it."
        ),
        "owner": "project owner",
        "evidence": (
            "FIX-03 license.declaration_evidence; legal_artifacts "
            "OPENZEPPELIN_LICENSE.txt."
        ),
    },
    "RIGHTS-05": {
        "action": (
            "Record the final rights and notice decision in "
            "tests/fixtures/README.md and this inventory before publishing "
            "the repository or a release archive."
        ),
        "owner": "release approver",
        "evidence": "rights_review.publication_decision is BLOCKED.",
    },
}

AUTHORIZED_PASS_DISCLAIMER = (
    "PASS only confirms the release-intent distribution inventory is truthfully "
    "recorded and technically reviewed (owner-authorized release intent with "
    "cited technical NOTICE review, Apache-2.0/MIT texts and fixture NOTICE). "
    "It does NOT authorize final publication, claim a legal conclusion, or "
    "assert a separate approval. It does NOT establish external release "
    "execution: GitHub environment protection, exact-commit main CI, tag "
    "existence, immutable-release setting verification, and attestations are "
    "enforced by the release workflow preflight, build jobs, and owner manual "
    "publication steps before any publication, and cannot be established "
    "offline. Final release controls remain outstanding. The release path is "
    "draft-only."
)

PASS_DISCLAIMER = (
    "PASS only confirms the blocked distribution inventory is truthfully "
    "recorded. It does NOT authorize publication, release, upload, or signing. "
    "Moving to an authorized (distributable) state requires reviewed code "
    "changes, not data-only edits to JSON files."
)


class VerificationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def require_object(value: object, label: str) -> dict:
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def require_list(value: object, label: str) -> list:
    require(isinstance(value, list), f"{label} must be a list")
    return value


def require_string(value: object, label: str) -> str:
    require(isinstance(value, str) and value, f"{label} must be a non-empty string")
    return value


def require_bool(value: object, label: str) -> bool:
    require(isinstance(value, bool), f"{label} must be a boolean")
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
    require(
        path.as_posix() == value,
        f"{label} is not a canonical relative path: {value}",
    )
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
    """Fail-closed glob match supporting ** alongside fnmatch semantics."""
    # Exact shortcut.
    if path == pattern:
        return True
    # Prefix form "some/dir/**" matches the dir itself and everything below it.
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        if path == prefix or path.startswith(prefix + "/"):
            return True
    # Suffix form "**/name" matches bare names and any nested path.
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


def check_no_symlink_component(root: Path, relative: str, label: str) -> None:
    """Fail if any existing filesystem prefix of root/relative is a symlink."""
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        try:
            status = current.lstat()
        except FileNotFoundError:
            return
        except OSError as error:
            raise VerificationError(
                f"cannot inspect {label} {relative}: {error}"
            ) from error
        require(
            not stat.S_ISLNK(status.st_mode),
            f"{label} path contains a symlink component: {relative}",
        )


def read_inventory_file(root: Path, relative: str, label: str) -> bytes:
    validate_relative_path(relative, f"{label} path")
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        try:
            status = current.lstat()
        except OSError as error:
            raise VerificationError(
                f"cannot read {label} {relative}: {error}"
            ) from error
        require(
            not stat.S_ISLNK(status.st_mode),
            f"{label} path contains a symlink component: {relative}",
        )
    require(stat.S_ISREG(status.st_mode), f"{label} must be a regular file: {relative}")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise VerificationError(f"{label} escapes the source root: {relative}") from error
    try:
        return current.read_bytes()
    except OSError as error:
        raise VerificationError(f"cannot read {label} {relative}: {error}") from error


def parse_json_object(data: bytes, label: str) -> dict:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError(f"{label} is not valid UTF-8: {error}") from error
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise VerificationError(f"invalid JSON in {label}: {error}") from error
    require(isinstance(value, dict), f"{label} must contain a JSON object")
    return value



def _load_gate_module() -> object:
    gate_path = Path(__file__).resolve().parent / "release" / "gate.py"
    spec = importlib.util.spec_from_file_location("astatine_release_gate", gate_path)
    if spec is None or spec.loader is None:
        raise VerificationError("cannot load release gate module")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    except Exception as error:
        raise VerificationError(f"cannot load release gate module: {error}") from error
    return module


def verify_authorized_via_gate(root: Path) -> dict:
    gate_module = _load_gate_module()
    try:
        gate = gate_module.load_gate(root)  # type: ignore[union-attr]
    except Exception as error:
        gate_error = getattr(gate_module, "GateError", None)
        if gate_error is not None and isinstance(error, gate_error):
            raise VerificationError(str(error)) from error
        if isinstance(error, (KeyError, TypeError, ValueError, AttributeError)):
            raise VerificationError(f"inventory/schema error: {error}") from error
        raise VerificationError("inventory verification failed") from error
    if gate.get("state") != "release-intent-authorized":
        raise VerificationError("release-intent gate dispatch received a non-release-intent state")
    intent_authorization = gate.get("release_intent_authorization") or {}
    technical_review = gate.get("technical_notice_review") or {}
    controls = gate.get("release_controls") or {}
    archive_members = gate.get("archive_members") or []
    generated_members = gate.get("generated_members") or []
    fixture_paths = gate.get("fixture_paths") or []
    return {
        "status": "PASS",
        "schema": "astatine-distribution-inventory/v3",
        "rights_decision": gate.get("rights_decision"),
        "release_intent_authorized": True,
        "publication_authorized": False,
        "final_release_controls_complete": False,
        "source_distribution": "RELEASE-INTENT-AUTHORIZED",
        "binary_distribution": "RELEASE-INTENT-AUTHORIZED",
        "notice_applicability": gate.get("notice_applicability"),
        "blocking_open": [],
        "notice_checklist_status": gate.get("notice_checklist_status"),
        "release_intent_authorization": intent_authorization.get("status"),
        "technical_notice_review": technical_review.get("reviewed_by"),
        "review_ci_branch_push_authorization": "SUPERSEDED \u2014 OWNER-AUTHORIZED RELEASE INTENT",
        "release_controls": controls.get("status"),
        "release_workflow": controls.get("workflow"),
        "release_environment": controls.get("environment"),
        "targets": list(gate.get("targets") or []),
        "archive_members_checked": len(archive_members) + len(generated_members),
        "source_members_checked": len(archive_members),
        "generated_members_checked": len(generated_members),
        "fixture_paths_checked": len(fixture_paths),
        "disclaimer": AUTHORIZED_PASS_DISCLAIMER,
    }


def verify_inventory(root: Path) -> dict:
    inventory_bytes = read_inventory_file(root, INVENTORY_REL, "distribution inventory")
    inventory = parse_json_object(inventory_bytes, INVENTORY_REL)
    if inventory.get("schema") == "astatine-distribution-inventory/v3":
        return verify_authorized_via_gate(root)
    require(
        inventory.get("schema") == EXPECTED_SCHEMA,
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
        "rights_gate blocking_open changed; expected "
        f"{EXPECTED_BLOCKING_OPEN!r}, got {list(blocking_open)!r}",
    )
    require(
        gate.get("fail_closed") is True,
        "rights_gate fail_closed must be true; data-only edits cannot authorize distribution",
    )
    require_string(gate.get("rule"), "rights_gate rule")
    gate_push_auth = require_object(
        gate.get("review_ci_branch_push_authorization"),
        "rights_gate review_ci_branch_push_authorization",
    )
    require(
        gate_push_auth == EXPECTED_REVIEW_PUSH_AUTH,
        "rights_gate review/CI branch push authorization changed; the limited "
        "review/CI scope must be recorded exactly",
    )

    source_dist = require_object(inventory.get("source_distribution"), "source_distribution")
    require(
        source_dist.get("status") == "BLOCKED",
        "source distribution must remain BLOCKED; data-only edits cannot authorize distribution",
    )
    require_string(source_dist.get("reason"), "source_distribution reason")

    binary = require_object(inventory.get("binary_distribution"), "binary_distribution")
    require(
        binary.get("status") == "BLOCKED",
        "binary distribution must remain BLOCKED; data-only edits cannot authorize distribution",
    )
    require_string(binary.get("reason"), "binary_distribution reason")
    require(
        binary.get("target") == EXPECTED_TARGET,
        f"binary_distribution target changed: {binary.get('target')!r}",
    )

    members = require_list(binary.get("archive_members"), "binary_distribution archive_members")
    require(members, "binary_distribution archive_members must not be empty")

    forbidden = require_list(binary.get("forbidden_globs"), "binary_distribution forbidden_globs")
    require(forbidden, "binary_distribution forbidden_globs must not be empty")
    forbidden_strings: list[str] = []
    for index, pattern in enumerate(forbidden):
        forbidden_strings.append(validate_glob(pattern, f"binary_distribution forbidden_globs[{index}]"))
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
    fixture_strings: list[str] = []
    for index, item in enumerate(fixture_paths):
        fixture_strings.append(
            validate_relative_path(item, f"binary_distribution fixture_paths[{index}]")
        )
    require(
        len(set(fixture_strings)) == len(fixture_strings),
        "binary_distribution fixture_paths contains duplicates",
    )

    seen_sources: set[str] = set()
    seen_archive_paths: set[str] = set()
    member_pairs: list[tuple[str, str]] = []
    for index, member in enumerate(members):
        label = f"binary_distribution archive_members[{index}]"
        member = require_object(member, label)
        source = validate_relative_path(member.get("source"), f"{label} source")
        archive_path = validate_relative_path(
            member.get("archive_path"), f"{label} archive_path"
        )
        required = member.get("required")
        require(required is True, f"{label} required must be true")
        require(source not in seen_sources, f"{label} duplicate archive member source: {source}")
        require(
            archive_path not in seen_archive_paths,
            f"{label} duplicate archive member archive_path: {archive_path}",
        )
        seen_sources.add(source)
        seen_archive_paths.add(archive_path)
        member_pairs.append((source, archive_path))
        # Fail closed before allowlist comparison so smuggled fixtures or
        # forbidden paths are reported as archive-exclusion violations.
        for fixture in fixture_strings:
            require(
                source != fixture and archive_path != fixture,
                f"{label} allows a fixture into the release archive: {fixture}",
            )
        for pattern in forbidden_strings:
            require(
                not glob_matches(source, pattern),
                f"{label} source is allowed by a forbidden glob into the release archive: "
                f"{source} matches {pattern}",
            )
            require(
                not glob_matches(archive_path, pattern),
                f"{label} archive_path is allowed by a forbidden glob into the release archive: "
                f"{archive_path} matches {pattern}",
            )
        check_no_symlink_component(root, source, label + " source")
    require(
        set(member_pairs) == set(EXPECTED_ARCHIVE_MEMBERS),
        "binary_distribution archive_members changed; the explicit allowlist is "
        f"{sorted(EXPECTED_ARCHIVE_MEMBERS)!r}, got {sorted(member_pairs)!r}",
    )
    require(
        len(member_pairs) == len(EXPECTED_ARCHIVE_MEMBERS),
        "binary_distribution archive_members must list exactly the allowlisted members",
    )
    for expected_source, expected_archive in EXPECTED_ARCHIVE_MEMBERS:
        require(
            (expected_source, expected_archive) in member_pairs,
            f"binary_distribution is missing required archive member: {expected_source}",
        )

    generated = require_list(binary.get("generated_members"), "binary_distribution generated_members")
    require(generated, "binary_distribution generated_members must not be empty")
    generated_pairs: list[tuple[str, str]] = []
    seen_generated_paths: set[str] = set()
    for index, member in enumerate(generated):
        label = f"binary_distribution generated_members[{index}]"
        member = require_object(member, label)
        archive_path = validate_relative_path(
            member.get("archive_path"), f"{label} archive_path"
        )
        generator = require_string(member.get("generator"), f"{label} generator")
        require(
            generator == EXPECTED_GENERATOR,
            f"{label} generator changed: {generator!r}",
        )
        validate_relative_path(generator, f"{label} generator")
        required = member.get("required")
        require(required is True, f"{label} required must be true")
        require(
            archive_path not in seen_generated_paths,
            f"{label} duplicate generated member archive_path: {archive_path}",
        )
        seen_generated_paths.add(archive_path)
        generated_pairs.append((archive_path, generator))
        # Generated metadata must never smuggle a fixture or forbidden path,
        # and must not collide with a source archive path.
        require(
            archive_path not in seen_archive_paths,
            f"{label} overlaps a source archive member path: {archive_path}",
        )
        for fixture in fixture_strings:
            require(
                archive_path != fixture,
                f"{label} allows a fixture into the release archive: {fixture}",
            )
        for pattern in forbidden_strings:
            require(
                not glob_matches(archive_path, pattern),
                f"{label} archive_path is allowed by a forbidden glob into the release archive: "
                f"{archive_path} matches {pattern}",
            )
        check_no_symlink_component(root, generator, label + " generator")
    require(
        generated_pairs == list(EXPECTED_GENERATED_MEMBERS),
        "binary_distribution generated_members changed; expected the ordered "
        f"{list(EXPECTED_GENERATED_MEMBERS)!r}, got {generated_pairs!r}",
    )
    # Cross-check the gate against the authoritative PROVENANCE.json.
    provenance_bytes = read_inventory_file(root, PROVENANCE_REL, "fixture provenance")
    provenance = parse_json_object(provenance_bytes, PROVENANCE_REL)
    rights = require_object(provenance.get("rights_review"), "rights_review")
    provenance_decision = require_string(rights.get("publication_decision"), "rights_review publication_decision")
    provenance_notice = require_string(rights.get("notice_applicability"), "rights_review notice_applicability")
    require(
        provenance_decision == EXPECTED_PUBLICATION_DECISION,
        "rights gate publication decision changed; distribution cannot proceed",
    )
    require(
        provenance_notice == EXPECTED_NOTICE_APPLICABILITY,
        "NOTICE applicability must remain UNRESOLVED",
    )
    require(
        rights.get("rights_holder_authority") == ATTESTED_RIGHTS,
        "rights status must remain honest; data-only edits cannot establish "
        "ownership, authority, or independent verification",
    )
    attestation = require_object(rights.get("owner_attestation"), "rights_review owner_attestation")
    require(
        attestation.get("status") == ATTESTED_RIGHTS,
        "owner attestation status must remain honest; data-only edits cannot "
        "claim independent verification",
    )
    require_bool(
        attestation.get("independent_verification"),
        "owner_attestation independent_verification",
    )
    require(
        attestation.get("independent_verification") is False,
        "owner attestation must not be represented as independent verification",
    )
    require(
        gate_decision == provenance_decision,
        "inventory publication_decision does not match tests/fixtures/PROVENANCE.json",
    )
    require(
        gate_notice == provenance_notice,
        "inventory notice_applicability does not match tests/fixtures/PROVENANCE.json",
    )
    provenance_push_auth = require_object(
        rights.get("review_ci_branch_push_authorization"),
        "rights_review review_ci_branch_push_authorization",
    )
    require(
        provenance_push_auth == EXPECTED_REVIEW_PUSH_AUTH,
        "PROVENANCE.json review/CI branch push authorization changed",
    )
    require(
        gate_push_auth == provenance_push_auth,
        "inventory review/CI branch push authorization does not match "
        "tests/fixtures/PROVENANCE.json",
    )

    checklist = require_object(rights.get("notice_checklist"), "rights_review notice_checklist")
    checklist_status = require_string(checklist.get("status"), "notice_checklist status")
    require(
        checklist_status == EXPECTED_CHECKLIST_STATUS,
        "notice checklist status changed; the gate must stay "
        "OPEN \u2014 publication remains BLOCKED",
    )
    items = require_list(checklist.get("items"), "notice_checklist items")
    require(items, "notice_checklist items must not be empty")
    by_id: dict[str, dict] = {}
    for index, item in enumerate(items):
        item = require_object(item, f"notice_checklist items[{index}]")
        item_id = require_string(item.get("id"), f"notice_checklist items[{index}] id")
        require(item_id not in by_id, f"notice_checklist contains duplicate id: {item_id}")
        by_id[item_id] = item
    for expected_id in EXPECTED_BLOCKING_OPEN:
        require(expected_id in by_id, f"rights gate is missing blocking item: {expected_id}")
        entry = by_id[expected_id]
        expected_detail = EXPECTED_BLOCKER_DETAILS[expected_id]
        require(
            entry.get("blocking") is True,
            f"rights gate item is not blocking: {expected_id}",
        )
        require(
            entry.get("status") == "OPEN",
            f"rights gate blocking item is not OPEN: {expected_id}",
        )
        require(
            entry.get("action") == expected_detail["action"],
            f"rights gate item action changed: {expected_id}; rewording the "
            "checklist cannot imply approval",
        )
        require(
            entry.get("owner") == expected_detail["owner"],
            f"rights gate item owner changed: {expected_id}",
        )
        require(
            entry.get("evidence") == expected_detail["evidence"],
            f"rights gate item evidence changed: {expected_id}",
        )
    open_blocking = sorted(
        item_id
        for item_id, entry in by_id.items()
        if entry.get("blocking") is True and entry.get("status") == "OPEN"
    )
    require(
        set(open_blocking) == EXPECTED_BLOCKING_OPEN_SET,
        "rights gate blocking-open set changed; expected "
        f"{sorted(EXPECTED_BLOCKING_OPEN_SET)!r}, got {open_blocking!r}",
    )
    require(
        set(blocking_open) == set(open_blocking),
        "inventory blocking_open does not match the open blocking items in PROVENANCE.json",
    )

    provenance_fixtures = require_list(provenance.get("fixtures"), "provenance fixtures")
    require(provenance_fixtures, "provenance fixtures must not be empty")
    provenance_paths: list[str] = []
    for index, entry in enumerate(provenance_fixtures):
        entry = require_object(entry, f"provenance fixtures[{index}]")
        provenance_paths.append(
            validate_relative_path(entry.get("path"), f"provenance fixtures[{index}] path")
        )
        require(
            "release_archive_member" in entry,
            f"provenance fixtures[{index}] is missing release_archive_member",
        )
        require(
            entry.get("release_archive_member") is False,
            f"provenance fixtures[{index}] must not be a release archive member: "
            f"{entry.get('path')}",
        )
    require(
        set(provenance_paths) == EXPECTED_FIXTURE_PATHS,
        "fixture set in PROVENANCE.json changed; refusing to authorize against a moved gate",
    )
    require(
        set(fixture_strings) == set(provenance_paths),
        "inventory fixture_paths do not match the fixture set in tests/fixtures/PROVENANCE.json",
    )
    require(
        set(fixture_strings) == EXPECTED_FIXTURE_PATHS,
        "inventory fixture_paths changed; no fixture may be added to or removed from the gate by data edits",
    )

    return {
        "status": "PASS",
        "schema": EXPECTED_SCHEMA,
        "publication_decision": provenance_decision,
        "publication_authorized": False,
        "source_distribution": "BLOCKED",
        "binary_distribution": "BLOCKED",
        "notice_applicability": provenance_notice,
        "blocking_open": list(EXPECTED_BLOCKING_OPEN),
        "rights_holder_authority": rights.get("rights_holder_authority"),
        "owner_attestation_status": attestation.get("status"),
        "owner_attestation_independent_verification": False,
        "notice_checklist_status": checklist_status,
        "review_ci_branch_push_authorization": gate_push_auth["status"],
        "archive_members_checked": len(member_pairs) + len(generated_pairs),
        "source_members_checked": len(member_pairs),
        "generated_members_checked": len(generated_pairs),
        "fixture_paths_checked": len(fixture_strings),
        "disclaimer": PASS_DISCLAIMER,
    }


def verify(root: Path) -> dict:
    try:
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise VerificationError(f"source root is not readable: {error}") from error
    require(resolved.is_dir(), f"source root is not a directory: {resolved}")
    try:
        return verify_inventory(resolved)
    except VerificationError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise VerificationError(f"inventory/schema error: {error}") from error
    except OSError as error:
        raise VerificationError(f"filesystem error: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail-closed verifier for the distribution inventory."
    )
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=None,
        help="source root containing support/release/distribution-inventory.json "
        "(default: parent of support/)",
    )
    args = parser.parse_args()
    try:
        root = args.root if args.root is not None else Path(__file__).resolve().parents[1]
        result = verify(root)
    except VerificationError as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}, indent=2), file=sys.stderr)
        return 1
    except OSError as error:
        print(
            json.dumps({"status": "FAIL", "error": f"filesystem error: {error}"}, indent=2),
            file=sys.stderr,
        )
        return 1
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        print(
            json.dumps({"status": "FAIL", "error": f"inventory/schema error: {error}"}, indent=2),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
