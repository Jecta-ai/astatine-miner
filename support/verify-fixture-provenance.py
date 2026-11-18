#!/usr/bin/env python3
"""Offline verifier for tests/fixtures/PROVENANCE.json.

Checks exact fixture bytes, hashes, Git blob identities, JSON content class,
bytecode lengths, compiler declarations, legal artifacts and name-scrub policy.
It performs no network, wallet, build, Anvil or production-runtime operation.

Path handling is deliberately strict: every inventory path must be a canonical
relative POSIX path, exactly one of the expected paths for its category, free of
symlinked components, and a regular file confined to the supplied source root.
Schema, decode and filesystem failures are translated into VerificationError
and reported as structured JSON by the command line entry point.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath

INVENTORY_PATH = "tests/fixtures/PROVENANCE.json"
FIXTURE_DIR = "tests/fixtures"
FORBIDDEN_KEYS = ("abi", "deployedBytecode", "metadata", "source", "sources")
HEX = set("0123456789abcdefABCDEF")
REPOSITORY_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?![A-Za-z0-9_.-])"
)

EXPECTED_FIXTURE_IDENTITIES = {
    "tests/fixtures/AstatineMiner.json": ("FIX-01", "contract_creation_bytecode", "AstatineMiner"),
    "tests/fixtures/AstatineGenesisCoordinator.json": (
        "FIX-02",
        "contract_creation_bytecode",
        "AstatineGenesisCoordinator",
    ),
    "tests/fixtures/MockAST.json": ("FIX-03", "contract_creation_bytecode", "MockAST"),
    "tests/fixtures/synthetic-injective-virtual-receipt.json": (
        "FIX-04",
        "synthetic_rpc_receipt",
        None,
    ),
}
EXPECTED_FIXTURE_PATHS = frozenset(EXPECTED_FIXTURE_IDENTITIES)
EXPECTED_DOCUMENT_PATHS = frozenset({"tests/fixtures/README.md"})
EXPECTED_LEGAL_ARTIFACT_PATHS_V1 = frozenset({"tests/fixtures/OPENZEPPELIN_LICENSE.txt"})
EXPECTED_LEGAL_ARTIFACT_PATHS_V2 = frozenset(
    {
        "tests/fixtures/OPENZEPPELIN_LICENSE.txt",
        "tests/fixtures/LICENSE-APACHE-2.0.txt",
        "tests/fixtures/LICENSE-MIT.txt",
        "tests/fixtures/NOTICE",
    }
)
# Backwards-compatible alias: the authorized inventory uses V2.
EXPECTED_LEGAL_ARTIFACT_PATHS = EXPECTED_LEGAL_ARTIFACT_PATHS_V1
APACHE_LICENSE_PATH = "tests/fixtures/LICENSE-APACHE-2.0.txt"
MIT_LICENSE_PATH = "tests/fixtures/LICENSE-MIT.txt"
NOTICE_PATH = "tests/fixtures/NOTICE"
OPENZEPPELIN_LICENSE_PATH = "tests/fixtures/OPENZEPPELIN_LICENSE.txt"
EXPECTED_SCHEMA_V1 = "astatine-fixture-provenance/v1"
EXPECTED_SCHEMA_V2 = "astatine-fixture-provenance/v2"
EXPECTED_SCHEMA_V3 = "astatine-fixture-provenance/v3"
EXPECTED_VERIFICATION_DATE_V3 = "2026-11-17"
EXPECTED_RELEASE_VERSION = "0.1.0-testnet.4"
EXPECTED_RELEASE_TAG = "v0.1.0-testnet.4"
EXPECTED_RELEASE_TAG_POLICY = "refs/tags/v0.1.0-testnet.4"
EXPECTED_RELEASE_REVIEWER_ID = 86115037
EXPECTED_RELEASE_REVIEWER_LOGIN = "emyrinj"
EXPECTED_RIGHTS_DECISION_V3 = (
    "OWNER-AUTHORIZED RELEASE INTENT \u2014 project owner authorized first-party source and binary distribution intent "
    "for v0.1.0-testnet.4 under the explicitly documented owner self-approval policy; technical NOTICE review recorded; "
    "final release controls outstanding; not a legal conclusion, not independent review, and not a separate approval."
)
EXPECTED_NOTICE_APPLICABILITY_V3 = (
    "TECHNICALLY REVIEWED \u2014 no separate upstream NOTICE file was found in the pinned contract fixture "
    "subtrees; the private EVM root NOTICE is scoped to a separate Rust subtree; Apache-2.0 license text and fixture "
    "NOTICE are included. This is an evidence-based technical review, not a legal conclusion or separate approval."
)
EXPECTED_CHECKLIST_STATUS_V3 = (
    "TECHNICAL REVIEW RECORDED \u2014 owner-authorized release intent under the explicit owner self-approval policy; "
    "final release controls outstanding"
)
EXPECTED_RELEASE_INTENT_STATUS = (
    "OWNER-AUTHORIZED RELEASE INTENT \u2014 FINAL CONTROLS OUTSTANDING \u2014 OWNER SELF-APPROVAL"
)
EXPECTED_RELEASE_INTENT_BY = "project owner"
EXPECTED_RELEASE_INTENT_ON = "2026-11-17"
EXPECTED_RELEASE_INTENT_SCOPE = (
    "Owner-authorized first-party source and binary distribution intent for v0.1.0-testnet.4 on macOS ARM64, Linux x86_64, and Windows x86_64 under an explicit owner self-approval policy; no independent reviewer or separate approver; "
    "final release controls remain outstanding."
)
EXPECTED_RELEASE_INTENT_ROLES = (
    "Project owner only; the owner explicitly authorized owner self-approval for the protected release environment. "
    "No independent reviewer and no separate release approver was appointed, consulted, or asserted; separation of "
    "duties is explicitly reduced and recorded as a security tradeoff."
)
EXPECTED_OWNER_SELF_APPROVAL_POLICY = {
    "status": "ACTIVE \u2014 OWNER SELF-APPROVAL",
    "approved_by": "project owner",
    "approved_on": "2026-11-17",
    "authorization_source": (
        "Project owner directive in the release implementation task: sustainable owner-controlled release without "
        "any external human reviewer; the owner expressly authorized the new version and the owner "
        "self-approval model."
    ),
    "scope": (
        "The owner account emyrinj (immutable numeric GitHub user id 86115037) is the sole required reviewer for the "
        "protected release environment and may approve a deployment initiated by the same account. The owner also "
        "manually publishes the verified draft."
    ),
    "independent_reviewer": False,
    "separation_of_duties": (
        "NONE \u2014 the same owner account initiates the workflow, approves the protected environment, and performs "
        "manual publication; no independent human approval is required or claimed."
    ),
    "security_tradeoff": (
        "Removes independent separation of duties and a second-person review. A compromised, malicious, or mistaken "
        "owner account can approve and publish without another human check."
    ),
    "residual_risk_accepted": True,
    "owner_attested": True,
    "independent_verification": False,
    "compensating_controls": [
        "exact release tag pinned to v0.1.0-testnet.4 and an exact-tag environment deployment policy",
        "environment cannot be bypassed by administrators (can_admins_bypass: false)",
        "separate tag creation ruleset must be active with the creation rule and exactly the owner-user bypass (User 86115037, always) for exactly refs/tags/v* with no exclusions; repository-admin bypass is rejected",
        "separate tag immutability ruleset must be active for update, deletion and non-fast-forward with zero bypass actors covering exactly refs/tags/v* with no exclusions",
        "tag creation protection must be retained; it must not be removed or broadened",
        "immutable releases must be enabled before dispatch and rechecked before publication",
        "exact-commit green main CI for Rust CI and Linux native qualification",
        "binary and archive build-provenance attestations bound to the exact tag and source digest",
        "draft-only creation; no automated publication",
        "owner-only repository write authority and post-publication verification",
        "all release records explicitly state that review is not independent",
    ],
    "not_claimed": [
        "independent review",
        "separation of duties",
        "a separate release approver",
        "legal conclusion",
        "immunity from owner-account compromise",
    ],
}
EXPECTED_HISTORICAL_RELEASE_INTENT = {
    "tag": "v0.1.0-testnet.1",
    "commit": "99a8630a7ae7f5c5950031dfba8c3b0c3f132cbc",
    "status": (
        "SUPERSEDED \u2014 UNPUBLISHED; historical tag and pending draft workflow retained; no publication occurred"
    ),
    "rights_decision": (
        "OWNER-AUTHORIZED RELEASE INTENT \u2014 project owner authorized first-party source and binary distribution "
        "intent for v0.1.0-testnet.1; technical NOTICE review recorded; final release controls outstanding; "
        "not a legal conclusion or separate approval."
    ),
    "scope": (
        "Owner-authorized first-party source and binary distribution intent for v0.1.0-testnet.1 on macOS ARM64 and "
        "Linux x86_64; final release controls remain outstanding."
    ),
    "approval_roles": (
        "Project owner only; no separate release approver was appointed, consulted, or asserted."
    ),
    "release_notes_path": "support/release/RELEASE_NOTES-v0.1.0-testnet.1.md",
    "release_notes_sha256": "12d7605b5e48c80f1c838a95d245c08da8cd5c831d008da3bb3dea420bdc31b9",
    "note": (
        "The .1 rights decision, scope and approval roles are preserved verbatim; the tag, commit, "
        "release-notes hash and status metadata are added to identify the historical record. The .1 tag is "
        "not moved; its workflow run is not cancelled or deleted; no .1 release was published. The current "
        ".4 authorization does not alter the preserved .1 fields."
    ),
}
EXPECTED_RELEASE_IDENTITY = {
    "version": EXPECTED_RELEASE_VERSION,
    "tag": EXPECTED_RELEASE_TAG,
    "tag_policy": EXPECTED_RELEASE_TAG_POLICY,
    "exact_tag_required": True,
}
EXPECTED_TECHNICAL_REVIEWED_BY = (
    "Repository technical review; not the project owner and not a separate release approver."
)
EXPECTED_TECHNICAL_FINDING = (
    "No upstream NOTICE file was found in the pinned contract fixture subtrees. The private EVM root contains an Apache "
    "NOTICE scoped to a separate Rust subtree; the contract subtrees have no NOTICE. Apache-2.0 license text and fixture "
    "NOTICE are included for source redistribution. This is an evidence-based technical review, not a legal conclusion or separate approval."
)
EXPECTED_TECHNICAL_CITATIONS = [
    "tests/fixtures/PROVENANCE.json",
    "tests/fixtures/README.md",
    "tests/fixtures/LICENSE-APACHE-2.0.txt",
    "tests/fixtures/LICENSE-MIT.txt",
    "tests/fixtures/OPENZEPPELIN_LICENSE.txt",
    "tests/fixtures/NOTICE",
]
EXPECTED_PUSH_STATUS_SUPERSEDED_V3 = "SUPERSEDED \u2014 OWNER-AUTHORIZED RELEASE INTENT"
EXPECTED_PUSH_SUPERSEDED_BY_V3 = "release_intent_authorization"
EXPECTED_PUSH_SUPERSEDED_ON = "2026-11-17"
EXPECTED_COPYRIGHT_EMY = "Copyright (c) 2026 emyrinj"
EXPECTED_SCRUB_PATHS_V1 = frozenset(
    {
        "README.md",
        "MACOS_ARM64.md",
        "support/update-evm-test-fixtures.py",
        "support/update-genesis-coordinator-fixture.py",
        "tests/fixtures/README.md",
    }
)
EXPECTED_SCRUB_PATHS_V3 = frozenset(
    {
        "README.md",
        "MACOS_ARM64.md",
        "src/protocol.rs",
        "support/update-evm-test-fixtures.py",
        "support/update-genesis-coordinator-fixture.py",
        "tests/fixtures/README.md",
    }
)
# Backwards-compatible alias: blocked v1 inventory uses V1; live v3 uses V3.
EXPECTED_SCRUB_PATHS = EXPECTED_SCRUB_PATHS_V1
EXPECTED_REGENERATION_SCRIPTS = frozenset(
    {
        "support/update-evm-test-fixtures.py",
        "support/update-genesis-coordinator-fixture.py",
    }
)
EXPECTED_REGENERATION_SCRIPT_BY_ID = {
    "FIX-01": "support/update-evm-test-fixtures.py",
    "FIX-02": "support/update-genesis-coordinator-fixture.py",
}

ATTESTED_RIGHTS = "OWNER-ATTESTED — not independently verified"
EXPECTED_PUBLICATION_DECISION = (
    "BLOCKED pending review of rights and notice applicability; "
    "first-party ownership is owner-attested and not independently verified."
)
EXPECTED_NOTICE_APPLICABILITY = "UNRESOLVED"
EXPECTED_CHECKLIST_STATUS = "OPEN — publication remains BLOCKED"
EXPECTED_REVIEW_PUSH_STATUS = "AUTHORIZED — REVIEW/CI ONLY"
EXPECTED_REVIEW_PUSH_DATE = "2026-11-16"
EXPECTED_REVIEW_PUSH_SCOPE = (
    "Push the fix/phase-e-e02-e07 remediation branch to the already-public "
    "repository solely for review and CI."
)
EXPECTED_REVIEW_PUSH_VISIBILITY = (
    "The repository is already public. That visibility does not authorize a "
    "source archive, binary archive or release, tag or release publication, "
    "or workflow attestation dispatch."
)
EXPECTED_REVIEW_PUSH_NOT_AUTHORIZED = [
    "source archive distribution",
    "binary archive or release distribution",
    "tag or public release publication",
    "workflow attestation dispatch",
    "broader license grant or legal clearance",
    "resolution of RIGHTS-02 through RIGHTS-05",
]
EXPECTED_REVIEW_PUSH_GATE_UNCHANGED = (
    "RIGHTS-02 through RIGHTS-05 remain OPEN and blocking; "
    "source_distribution and binary_distribution remain BLOCKED."
)
EXPECTED_INTENT_REVIEW_PUSH_GATE = (
    "As of 2026-11-16, superseded 2026-11-17: RIGHTS-02 through RIGHTS-05 were OPEN and blocking; "
    "source_distribution and binary_distribution were BLOCKED."
)
EXPECTED_PRIOR_ATTESTATION = {
    "status": "OWNER-ATTESTED \u2014 not independently verified",
    "scope": "The AstatineMiner and AstatineGenesisCoordinator contracts are first-party works developed and owned by the project owner.",
    "attested_on": "2026-11-15",
    "attestation_source": "The project owner explicitly confirmed ownership of the first-party ASTATINE mining and genesis coordinator contracts for Phase D; not independently verified.",
    "independent_verification": False,
}
EXPECTED_REVIEW_PUSH_AUTH = {
    "status": EXPECTED_REVIEW_PUSH_STATUS,
    "authorized_by": "project owner",
    "authorized_on": EXPECTED_REVIEW_PUSH_DATE,
    "scope": EXPECTED_REVIEW_PUSH_SCOPE,
    "public_repository_visibility": EXPECTED_REVIEW_PUSH_VISIBILITY,
    "not_authorized": EXPECTED_REVIEW_PUSH_NOT_AUTHORIZED,
    "rights_gate_unchanged": EXPECTED_REVIEW_PUSH_GATE_UNCHANGED,
}
# Pinned canonical notice-checklist entries for the blocking items. A reworded
# action, owner, or evidence string must fail; no legal approval is inferred.
# Kept in this file so the fixture verifier stands independent of the
# distribution inventory verifier.
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

FIXTURE_REQUIRED_FIELDS = (
    "id",
    "path",
    "kind",
    "contract",
    "source_origin",
    "source_commit",
    "canonical_git_blob_sha1",
    "sha256",
    "bytes",
    "json_keys",
    "bytecode",
    "compiler",
    "compiler_evidence",
    "runtime_purpose",
    "production_runtime_use",
    "release_archive_member",
    "consumers",
    "license",
    "regeneration",
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


def require_string(value: object, label: str, *, allow_none: bool = False) -> str | None:
    if allow_none and value is None:
        return None
    require(isinstance(value, str) and value, f"{label} must be a non-empty string")
    return value


def require_int(value: object, label: str, *, minimum: int = 0) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{label} must be an integer")
    require(value >= minimum, f"{label} must be >= {minimum}")
    return value


def require_bool(value: object, label: str) -> bool:
    require(isinstance(value, bool), f"{label} must be a boolean")
    return value


def require_sha256(value: object, label: str) -> str:
    require(
        isinstance(value, str)
        and len(value) == 64
        and set(value) <= set("0123456789abcdef"),
        f"{label} must be lowercase SHA-256 hex",
    )
    return value


def require_git_sha1(value: object, label: str) -> str:
    require(
        isinstance(value, str)
        and len(value) == 40
        and set(value) <= set("0123456789abcdef"),
        f"{label} must be lowercase SHA-1 hex",
    )
    return value


def require_fields(mapping: dict, fields: tuple[str, ...], label: str) -> None:
    missing = [field for field in fields if field not in mapping]
    require(not missing, f"{label} is missing required fields: {missing}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data).hexdigest()


def sanitize_log_text(value: object) -> str:
    """Render untrusted filesystem/error text as one printable ASCII line.

    Fixture filenames and OSError strings can contain newlines or control
    characters. Checks continue to use the original value; only the
    diagnostic rendering is escaped so it cannot inject terminal/log lines.
    """
    return str(value).encode("unicode_escape").decode("ascii")


def fixture_rel_path(inventory_path: str) -> str | None:
    """Return the fixture-relative POSIX path for inventory paths under FIXTURE_DIR."""
    try:
        rel = PurePosixPath(inventory_path).relative_to(FIXTURE_DIR)
    except ValueError:
        return None
    if not rel.parts or any(part in ("", ".", "..") for part in rel.parts):
        return None
    return rel.as_posix()


def validate_relative_path(value: object, label: str) -> str:
    require(isinstance(value, str) and value, f"{label} must be a non-empty relative path string")
    require("\x00" not in value, f"{label} must not contain NUL")
    require("\\" not in value, f"{label} must use POSIX separators")
    path = PurePosixPath(value)
    require(not path.is_absolute(), f"{label} must not be absolute: {value}")
    parts = path.parts
    require(parts and all(part not in ("", ".", "..") for part in parts), f"{label} contains traversal: {value}")
    require(path.as_posix() == value, f"{label} is not a canonical relative path: {value}")
    return value


def read_confined_bytes(
    root: Path,
    relative: object,
    label: str,
    expected_paths: frozenset[str] | None = None,
) -> tuple[str, bytes]:
    text = validate_relative_path(relative, label)
    if expected_paths is not None:
        require(text in expected_paths, f"{label} path is not expected: {text}")
    current = root
    for part in PurePosixPath(text).parts:
        current = current / part
        try:
            status = current.lstat()
        except OSError as error:
            raise VerificationError(f"cannot read {label} {text}: {error}") from error
        require(
            not stat.S_ISLNK(status.st_mode),
            f"{label} path contains a symlink component: {text}",
        )
    require(stat.S_ISREG(status.st_mode), f"{label} must be a regular file: {text}")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise VerificationError(f"{label} escapes the source root: {text}") from error
    try:
        return text, current.read_bytes()
    except OSError as error:
        raise VerificationError(f"cannot read {label} {text}: {error}") from error


def decode_utf8(data: bytes, label: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError(f"{label} is not valid UTF-8: {error}") from error


def parse_json_object(data: bytes, label: str) -> dict:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid JSON in {label}: {error}") from error
    require(isinstance(value, dict), f"{label} must contain a JSON object")
    return value


def validate_inventory_metadata(inventory: dict) -> None:
    scope = inventory.get("scope")
    require(isinstance(scope, str) and scope, "inventory scope must be a non-empty string")

    baseline = require_object(inventory.get("baseline"), "baseline")
    require_fields(baseline, ("canonical_repository_head", "canonical_tree", "note"), "baseline")
    require_git_sha1(baseline["canonical_repository_head"], "baseline canonical_repository_head")
    require_git_sha1(baseline["canonical_tree"], "baseline canonical_tree")
    require_string(baseline["note"], "baseline note")

    verification = require_object(inventory.get("verification"), "verification")
    require_fields(
        verification,
        (
            "command",
            "test_command",
            "network_required",
            "build_required",
            "regenerated_in_this_review",
            "date_utc",
        ),
        "verification",
    )
    require_string(verification["command"], "verification command")
    require_string(verification["test_command"], "verification test_command")
    require_bool(verification["network_required"], "verification network_required")
    require_bool(verification["build_required"], "verification build_required")
    require_bool(
        verification["regenerated_in_this_review"],
        "verification regenerated_in_this_review",
    )
    require_string(verification["date_utc"], "verification date_utc")


def validate_fixture_entry(entry: object, index: int) -> None:
    label = f"fixtures[{index}]"
    entry = require_object(entry, label)
    require_fields(entry, FIXTURE_REQUIRED_FIELDS, label)
    require_string(entry["id"], f"{label} id")
    validate_relative_path(entry["path"], f"{label} path")
    require(entry["path"] in EXPECTED_FIXTURE_PATHS, f"{label} path is not an expected fixture: {entry['path']}")
    kind = require_string(entry["kind"], f"{label} kind")
    require(kind in {"contract_creation_bytecode", "synthetic_rpc_receipt"}, f"{label} kind is unknown: {kind}")
    require_string(entry["source_origin"], f"{label} source_origin")
    require_string(entry["contract"], f"{label} contract", allow_none=True)
    require_string(entry["source_commit"], f"{label} source_commit", allow_none=True)
    expected_id, expected_kind, expected_contract = EXPECTED_FIXTURE_IDENTITIES[entry["path"]]
    require(
        (entry["id"], entry["kind"], entry["contract"]) == (expected_id, expected_kind, expected_contract),
        f"{label} path substitution changes the expected fixture identity: {entry['path']}",
    )
    require_git_sha1(entry["canonical_git_blob_sha1"], f"{label} canonical_git_blob_sha1")
    require_sha256(entry["sha256"], f"{label} sha256")
    require_int(entry["bytes"], f"{label} bytes")
    json_keys = require_list(entry["json_keys"], f"{label} json_keys")
    require(json_keys, f"{label} json_keys must not be empty")
    require(all(isinstance(key, str) and key for key in json_keys), f"{label} json_keys must be strings")
    require(len(set(json_keys)) == len(json_keys), f"{label} json_keys contains duplicates")
    require_string(entry["compiler_evidence"], f"{label} compiler_evidence")
    require_string(entry["runtime_purpose"], f"{label} runtime_purpose")
    require_bool(entry["production_runtime_use"], f"{label} production_runtime_use")
    require_bool(entry["release_archive_member"], f"{label} release_archive_member")
    require(
        entry["release_archive_member"] is False,
        f"{label} must not be a release archive member: {entry['path']}",
    )
    consumers = require_list(entry["consumers"], f"{label} consumers")
    require(consumers, f"{label} consumers must not be empty")
    require(all(isinstance(value, str) and value for value in consumers), f"{label} consumers must be strings")

    compiler = entry["compiler"]
    if compiler is not None:
        compiler = require_object(compiler, f"{label} compiler")
        require_fields(
            compiler,
            ("version", "evm_version", "optimizer", "optimizer_runs", "bytecode_hash"),
            f"{label} compiler",
        )
        require_string(compiler["version"], f"{label} compiler version")
        require_string(compiler["evm_version"], f"{label} compiler evm_version")
        require_bool(compiler["optimizer"], f"{label} compiler optimizer")
        require_int(compiler["optimizer_runs"], f"{label} compiler optimizer_runs")
        require_string(compiler["bytecode_hash"], f"{label} compiler bytecode_hash")

    bytecode = entry["bytecode"]
    if kind == "contract_creation_bytecode":
        require(entry["contract"] is not None, f"{label} contract is required for bytecode fixtures")
        require(entry["source_commit"] is not None, f"{label} source_commit is required for bytecode fixtures")
        bytecode = require_object(bytecode, f"{label} bytecode")
        require_fields(bytecode, ("encoding", "hex_chars", "bytes", "sha256"), f"{label} bytecode")
        require_string(bytecode["encoding"], f"{label} bytecode encoding")
        require_int(bytecode["hex_chars"], f"{label} bytecode hex_chars")
        require_int(bytecode["bytes"], f"{label} bytecode bytes")
        require_sha256(bytecode["sha256"], f"{label} bytecode sha256")
    else:
        require(bytecode is None, f"{label} receipt fixture must not declare bytecode")
        require(entry["contract"] is None, f"{label} receipt contract must be null")
        require(entry["source_commit"] is None, f"{label} receipt source_commit must be null")

    license_info = require_object(entry["license"], f"{label} license")
    require_fields(license_info, ("declared_spdx", "declaration_evidence", "rights_status"), f"{label} license")
    require_string(license_info["declared_spdx"], f"{label} license declared_spdx", allow_none=True)
    require_string(license_info["declaration_evidence"], f"{label} license declaration_evidence")
    require_string(license_info["rights_status"], f"{label} license rights_status")

    regeneration = require_object(entry["regeneration"], f"{label} regeneration")
    require_fields(regeneration, ("status", "performed_in_this_review"), f"{label} regeneration")
    status = require_string(regeneration["status"], f"{label} regeneration status")
    require(
        status in {"scripted", "not_scripted", "captured_not_regenerated"},
        f"{label} regeneration status is unknown: {status}",
    )
    require_bool(regeneration["performed_in_this_review"], f"{label} regeneration performed_in_this_review")
    if status == "scripted":
        require_fields(regeneration, ("script", "script_sha256", "requires"), f"{label} regeneration")
        require_string(regeneration["script"], f"{label} regeneration script")
        require_sha256(regeneration["script_sha256"], f"{label} regeneration script_sha256")
        require_string(regeneration["requires"], f"{label} regeneration requires")
    else:
        require_string(regeneration["detail"], f"{label} regeneration detail")


def validate_fixture_licenses_authorized(entries: list) -> None:
    by_id = {entry.get("id"): entry for entry in entries if isinstance(entry, dict)}
    for fid in ("FIX-01", "FIX-02"):
        require(fid in by_id, f"authorized inventory is missing {fid}")
        lic = require_object(by_id[fid].get("license"), f"{fid} license")
        require(
            lic.get("license_text") == APACHE_LICENSE_PATH,
            f"{fid} license_text must be {APACHE_LICENSE_PATH} for the authorized inventory",
        )
        require(
            lic.get("copyright") == EXPECTED_COPYRIGHT_EMY,
            f"{fid} copyright must be {EXPECTED_COPYRIGHT_EMY}",
        )
        status = require_string(lic.get("rights_status"), f"{fid} license rights_status")
        lowered = status.lower()
        require("first-party" in lowered, f"{fid} rights_status must state first-party ownership")
        require("apache-2.0" in lowered, f"{fid} rights_status must reference Apache-2.0")
        require("notice" in lowered, f"{fid} rights_status must reference the fixture NOTICE")
        require(
            "owner-attested" in lowered,
            f"{fid} rights_status must remain owner-attested and not independently verified",
        )
        require(
            "not independently verified" in lowered,
            f"{fid} rights_status must state it is not independently verified",
        )
        require(
            by_id[fid].get("license", {}).get("declared_spdx") == "Apache-2.0",
            f"{fid} declared_spdx changed",
        )
    require("FIX-03" in by_id, "authorized inventory is missing FIX-03")
    lic3 = require_object(by_id["FIX-03"].get("license"), "FIX-03 license")
    require(
        lic3.get("license_text") == MIT_LICENSE_PATH,
        f"FIX-03 license_text must be {MIT_LICENSE_PATH} for the authorized inventory",
    )
    require(
        lic3.get("copyright") == EXPECTED_COPYRIGHT_EMY,
        "FIX-03 copyright must be Copyright (c) 2026 emyrinj",
    )
    status3 = require_string(lic3.get("rights_status"), "FIX-03 license rights_status")
    lowered3 = status3.lower()
    require("mockast" in lowered3, "FIX-03 rights_status must identify MockAST")
    require("first-party" in lowered3, "FIX-03 rights_status must state first-party ownership")
    require("mit" in lowered3, "FIX-03 rights_status must reference MIT redistribution")
    require(
        "openzeppelin" in lowered3,
        "FIX-03 rights_status must retain the OpenZeppelin MIT notice",
    )
    require(
        "owner-attested" in lowered3,
        "FIX-03 rights_status must remain owner-attested and not independently verified",
    )
    require(
        "not independently verified" in lowered3,
        "FIX-03 rights_status must state it is not independently verified",
    )
    require(
        "authorized by the project owner" in lowered3,
        "FIX-03 rights_status must state MIT redistribution is authorized by the project owner",
    )
    require(
        by_id["FIX-03"].get("license", {}).get("declared_spdx") == "MIT",
        "FIX-03 declared_spdx changed",
    )
    require("FIX-04" in by_id, "authorized inventory is missing FIX-04")
    lic4 = require_object(by_id["FIX-04"].get("license"), "FIX-04 license")
    require(
        "license_text" not in lic4,
        "FIX-04 must remain synthetic and must not invent third-party license_text",
    )
    require(
        "copyright" not in lic4,
        "FIX-04 must remain synthetic and must not invent third-party copyright",
    )
    status4 = require_string(lic4.get("rights_status"), "FIX-04 license rights_status")
    require(
        "no third-party" in status4.lower(),
        "FIX-04 rights_status must remain synthetic with no third-party rights",
    )


def verify_bytecode(entry: dict, document: dict) -> None:
    require("bytecode" in document, f"{entry['path']} is missing bytecode")
    bytecode = document.get("bytecode")
    require(isinstance(bytecode, dict), f"{entry['path']} bytecode must be an object")
    require(set(bytecode) == {"object"}, f"{entry['path']} bytecode keys changed")
    value = bytecode["object"]
    require(isinstance(value, str), f"{entry['path']} bytecode must be a string")
    require(value.startswith("0x") and len(value) > 2, f"{entry['path']} bytecode must be 0x-prefixed")
    require(len(value) % 2 == 0, f"{entry['path']} bytecode hex length must be even")
    require(all(character in HEX for character in value[2:]), f"{entry['path']} bytecode is not hex")
    raw = bytes.fromhex(value[2:])
    expected = entry["bytecode"]
    require(len(raw) == expected["bytes"], f"{entry['path']} bytecode byte length changed")
    require(len(value) - 2 == expected["hex_chars"], f"{entry['path']} bytecode hex length changed")
    require(sha256_hex(raw) == expected["sha256"], f"{entry['path']} bytecode digest changed")


def verify_fixture(root: Path, entry: dict) -> None:
    relative, data = read_confined_bytes(
        root, entry["path"], f"fixture {entry['id']}", EXPECTED_FIXTURE_PATHS
    )
    require(len(data) == entry["bytes"], f"{relative} byte length changed")
    require(sha256_hex(data) == entry["sha256"], f"{relative} SHA-256 changed")
    require(git_blob_sha1(data) == entry["canonical_git_blob_sha1"], f"{relative} Git blob identity changed")

    document = parse_json_object(data, relative)
    require(set(document) == set(entry["json_keys"]), f"{relative} top-level JSON keys changed")
    for forbidden in FORBIDDEN_KEYS:
        require(forbidden not in document, f"{relative} contains forbidden key {forbidden}")

    if entry["kind"] == "contract_creation_bytecode":
        require(document.get("contract") == entry["contract"], f"{relative} contract changed")
        require(document.get("source_commit") == entry["source_commit"], f"{relative} source pin changed")
        verify_bytecode(entry, document)
        require(
            document.get("compiler") == entry["compiler"],
            f"{relative} compiler declaration changed",
        )
    elif entry["kind"] == "synthetic_rpc_receipt":
        require("source_commit" not in document, f"{relative} must not gain a source pin")
        require(document.get("transactionHash", "").startswith("0x"), "receipt transaction hash is missing")
        require(document.get("blockNumber", "").startswith("0x"), "receipt block number is missing")
        logs = document.get("logs")
        require(isinstance(logs, list), f"{relative} receipt logs must be a list")
        require(len(logs) == 8, f"{relative} synthetic receipt log count changed")
        virtual = [log for log in logs if isinstance(log, dict) and log.get("virtual") is True]
        require(len(virtual) == 5, f"{relative} synthetic virtual-log count changed")
        require(
            len(virtual) < len(logs),
            f"{relative} synthetic receipt must retain EVM event logs",
        )
    else:
        raise VerificationError(f"unknown fixture kind: {entry['kind']}")


def verify_regeneration_script(root: Path, entry: dict) -> None:
    """Verify a scripted regeneration entry against its recorded script hash.

    Authorized v3 path only. The script must exist under the source root as a
    regular confined file and its SHA-256 must equal the recorded
    ``script_sha256``. Missing, non-regular, or mismatched scripts fail closed.
    Blocked v1 behavior is unchanged (this helper is never called for v1).
    """
    regeneration = entry.get("regeneration", {})
    require(isinstance(regeneration, dict), f"{entry.get('id', '?')} regeneration must be an object")
    require(
        regeneration.get("status") == "scripted",
        f"{entry.get('id', '?')} regeneration status is not scripted",
    )
    script = regeneration.get("script")
    expected_digest = regeneration.get("script_sha256")
    require_string(script, f"{entry.get('id', '?')} regeneration script")
    require_sha256(expected_digest, f"{entry.get('id', '?')} regeneration script_sha256")
    require(
        script in EXPECTED_REGENERATION_SCRIPTS,
        f"{entry.get('id', '?')} regeneration script is not expected: {script}",
    )
    fixture_id = require_string(entry.get("id"), "regeneration fixture id")
    require(
        EXPECTED_REGENERATION_SCRIPT_BY_ID.get(fixture_id) == script,
        f"{fixture_id} regeneration script mapping changed; expected "
        f"{EXPECTED_REGENERATION_SCRIPT_BY_ID.get(fixture_id)!r}",
    )
    _, data = read_confined_bytes(root, script, f"regeneration script {entry.get('id', '?')}")
    require(
        sha256_hex(data) == expected_digest,
        f"regeneration script SHA-256 changed for {entry.get('id', '?')}: {script}",
    )


def verify_inventory(root: Path) -> dict:
    _, inventory_bytes = read_confined_bytes(
        root, INVENTORY_PATH, "inventory", frozenset({INVENTORY_PATH})
    )
    inventory = parse_json_object(inventory_bytes, INVENTORY_PATH)
    schema = inventory.get("schema")
    require(
        schema in (EXPECTED_SCHEMA_V1, EXPECTED_SCHEMA_V3),
        "unexpected inventory schema",
    )
    if schema == EXPECTED_SCHEMA_V2:
        raise VerificationError("fixture provenance v2 is superseded by v3; live schema must be v3")
    is_authorized = schema == EXPECTED_SCHEMA_V3
    expected_legal_paths = (
        EXPECTED_LEGAL_ARTIFACT_PATHS_V2 if is_authorized else EXPECTED_LEGAL_ARTIFACT_PATHS_V1
    )
    validate_inventory_metadata(inventory)
    if is_authorized:
        require(
            inventory.get("release") == EXPECTED_RELEASE_IDENTITY,
            "fixture provenance release identity must be exactly v0.1.0-testnet.4",
        )
        require(
            inventory.get("historical_release_intent") == EXPECTED_HISTORICAL_RELEASE_INTENT,
            "fixture provenance must preserve the historical .1 release intent record exactly",
        )
        require_sha256(
            EXPECTED_HISTORICAL_RELEASE_INTENT["release_notes_sha256"],
            "historical .1 release notes sha256",
        )
        # Fail closed on invented approver / final-publication language in live schema.
        _raw_lower = json.dumps(inventory, sort_keys=True).lower()
        require(
            "project owner and release approver" not in _raw_lower,
            "live schema must not invent a release approver",
        )
        require(
            "publication_authorization" not in _raw_lower,
            "live schema must not contain publication_authorization; use release_intent_authorization",
        )
        require(
            "publication_decision" not in _raw_lower,
            "live schema must not contain publication_decision; use rights_decision",
        )
        require(
            "publication authorized" not in _raw_lower,
            "live schema must not claim final publication authorization",
        )
        require(
            "complete \u2014 publication authorized" not in _raw_lower,
            "live schema must not claim final publication authorization",
        )
        verification = inventory.get("verification")
        require(isinstance(verification, dict), "verification must be an object")
        require(
            verification.get("date_utc") == EXPECTED_VERIFICATION_DATE_V3,
            "verification date_utc must be 2026-11-17 for the v3 inventory",
        )
        scope = inventory.get("scope")
        require(isinstance(scope, str), "inventory scope must be a non-empty string")
        lowered_scope = scope.lower()
        require(
            "offline fixture inventory" in lowered_scope and "unchanged" in lowered_scope,
            "v3 inventory scope must note the offline fixture inventory is unchanged",
        )
        require(
            "release intent" in lowered_scope,
            "v3 inventory scope must note owner-authorized release intent",
        )
        require(
            "technical" in lowered_scope,
            "v3 inventory scope must note technical NOTICE review",
        )
        require(
            "publication authorization" not in lowered_scope,
            "v3 inventory scope must not claim publication authorization",
        )
        # change_note must not reintroduce final-publication language
        _change = str(verification.get("change_note", "")).lower()
        require(
            "publication authorization" not in _change,
            "verification change_note must not claim publication authorization",
        )
        require(
            "project owner and release approver" not in _change,
            "verification change_note must not invent a release approver",
        )

    entries = require_list(inventory.get("fixtures"), "fixtures")
    require(entries, "inventory has no fixtures")
    for index, entry in enumerate(entries):
        validate_fixture_entry(entry, index)
    if is_authorized:
        validate_fixture_licenses_authorized(entries)
    entry_paths = [entry["path"] for entry in entries]
    require(len(set(entry_paths)) == len(entry_paths), "inventory contains duplicate fixture paths")
    require(set(entry_paths) == EXPECTED_FIXTURE_PATHS, "fixture path inventory changed")

    fixture_dir = root / FIXTURE_DIR
    require(fixture_dir.is_dir() and not fixture_dir.is_symlink(), "fixture directory is missing or a symlink")
    expected_fixture_rels = {
        rel for path in EXPECTED_FIXTURE_PATHS if (rel := fixture_rel_path(path)) is not None
    }
    expected_dir_files = {
        rel
        for path in (
            *EXPECTED_FIXTURE_PATHS,
            *EXPECTED_DOCUMENT_PATHS,
            *expected_legal_paths,
            INVENTORY_PATH,
        )
        if (rel := fixture_rel_path(path)) is not None
    }
    actual_names: set[str] = set()
    # R-02: extension-independent, recursive membership check confined to
    # tests/fixtures. Every entry is examined via lstat (no symlink following,
    # no extension filter, dotfiles included). Only the expected regular
    # files are allowed; any symlink, directory, or other non-regular entry at
    # any depth, any unlisted regular file, and any expected path that is not
    # a regular file fails closed with the offending fixture-relative path.
    violations: list[tuple[str, str]] = []
    pending: list[tuple[Path, str]] = [(fixture_dir, "")]
    try:
        while pending:
            current_dir, prefix = pending.pop()
            with os.scandir(current_dir) as items:
                ordered = sorted(list(items), key=lambda entry: entry.name)
                for item in ordered:
                    rel = item.name if prefix == "" else f"{prefix}/{item.name}"
                    display_rel = sanitize_log_text(rel)
                    if item.is_symlink():
                        violations.append(
                            (
                                rel,
                                f"fixture directory contains a symlink: {display_rel}",
                            )
                        )
                    elif item.is_dir(follow_symlinks=False):
                        if rel in expected_fixture_rels:
                            violations.append(
                                (
                                    rel,
                                    "fixture JSON entry must be a regular file: "
                                    f"{sanitize_log_text(item.name)}",
                                )
                            )
                        else:
                            violations.append(
                                (
                                    rel,
                                    "fixture directory contains an unexpected "
                                    f"directory: {display_rel}",
                                )
                            )
                        pending.append((Path(item.path), rel))
                    elif item.is_file(follow_symlinks=False):
                        if rel not in expected_dir_files:
                            violations.append(
                                (
                                    rel,
                                    "fixture directory contains an unexpected "
                                    f"file: {display_rel}",
                                )
                            )
                        elif rel in expected_fixture_rels:
                            actual_names.add(rel)
                    else:
                        if rel in expected_fixture_rels:
                            violations.append(
                                (
                                    rel,
                                    "fixture JSON entry must be a regular file: "
                                    f"{sanitize_log_text(item.name)}",
                                )
                            )
                        elif rel in expected_dir_files:
                            violations.append(
                                (
                                    rel,
                                    "fixture entry must be a regular file: "
                                    f"{display_rel}",
                                )
                            )
                        else:
                            violations.append(
                                (
                                    rel,
                                    "fixture directory contains an unexpected "
                                    f"entry: {display_rel}",
                                )
                            )
    except OSError as error:
        errno_value = getattr(error, "errno", None)
        errno_text = str(errno_value) if isinstance(errno_value, int) else "unknown"
        raise VerificationError(
            "cannot scan fixture directory "
            f"{sanitize_log_text(FIXTURE_DIR)}: "
            f"{sanitize_log_text(type(error).__name__)} (errno {errno_text})"
        ) from error
    if violations:
        violations.sort(key=lambda pair: pair[0])
        raise VerificationError(violations[0][1])
    require(actual_names == expected_fixture_rels, "fixture JSON file set changed")

    for entry in entries:
        verify_fixture(root, entry)

    if is_authorized:
        # R7: every scripted regeneration entry must resolve to a regular
        # confined file whose SHA-256 equals the recorded script_sha256.
        scripted_ids = set()
        for entry in entries:
            regeneration = entry.get("regeneration", {})
            if isinstance(regeneration, dict) and regeneration.get("status") == "scripted":
                verify_regeneration_script(root, entry)
                scripted_ids.add(require_string(entry.get("id"), "regeneration fixture id"))
        require(
            scripted_ids == set(EXPECTED_REGENERATION_SCRIPT_BY_ID),
            "scripted regeneration coverage must include FIX-01 and FIX-02 with their expected scripts",
        )

    documents = require_list(inventory.get("documents"), "documents")
    require(documents, "documents must not be empty")
    document_paths = []
    for index, document in enumerate(documents):
        label = f"documents[{index}]"
        document = require_object(document, label)
        require_fields(document, ("path", "sha256", "bytes"), label)
        path = validate_relative_path(document["path"], f"{label} path")
        require(path in EXPECTED_DOCUMENT_PATHS, f"{label} path is not expected: {path}")
        require_sha256(document["sha256"], f"{label} sha256")
        require_int(document["bytes"], f"{label} bytes")
        document_paths.append(path)
        _, data = read_confined_bytes(root, path, label, EXPECTED_DOCUMENT_PATHS)
        require(len(data) == document["bytes"], f"{path} byte length changed")
        require(sha256_hex(data) == document["sha256"], f"{path} SHA-256 changed")
    require(len(set(document_paths)) == len(document_paths), "duplicate document paths")
    require(set(document_paths) == EXPECTED_DOCUMENT_PATHS, "document path inventory changed")

    legal_artifacts = require_list(inventory.get("legal_artifacts"), "legal_artifacts")
    require(legal_artifacts, "legal artifact inventory is empty")
    legal_paths = []
    legal_by_path: dict[str, tuple[dict, bytes]] = {}
    for index, artifact in enumerate(legal_artifacts):
        label = f"legal_artifacts[{index}]"
        artifact = require_object(artifact, label)
        require_fields(artifact, ("path", "sha256", "bytes", "license", "copyright", "provenance", "evidence"), label)
        path = validate_relative_path(artifact["path"], f"{label} path")
        require(path in expected_legal_paths, f"{label} path is not expected: {path}")
        require_sha256(artifact["sha256"], f"{label} sha256")
        require_int(artifact["bytes"], f"{label} bytes")
        require_string(artifact["license"], f"{label} license")
        require_string(artifact["copyright"], f"{label} copyright")
        require_string(artifact["provenance"], f"{label} provenance")
        require_string(artifact["evidence"], f"{label} evidence")
        legal_paths.append(path)
        _, data = read_confined_bytes(root, path, label, expected_legal_paths)
        require(len(data) == artifact["bytes"], f"{path} byte length changed")
        require(sha256_hex(data) == artifact["sha256"], f"{path} SHA-256 changed")
        if path == OPENZEPPELIN_LICENSE_PATH:
            require(b"The MIT License (MIT)" in data, f"{path} is not the MIT license text")
            require(artifact["license"] == "MIT", f"{label} license must be MIT")
            require(
                artifact["copyright"] == "Copyright (c) 2016-2023 zOS Global Limited and contributors",
                f"{label} copyright changed",
            )
        elif path == APACHE_LICENSE_PATH:
            require(is_authorized, f"{path} is only expected in the authorized inventory")
            require(artifact["license"] == "Apache-2.0", f"{label} license must be Apache-2.0")
            require(
                artifact["copyright"] == EXPECTED_COPYRIGHT_EMY,
                f"{label} copyright must be {EXPECTED_COPYRIGHT_EMY}",
            )
            require(b"Apache License" in data, f"{path} is not the Apache-2.0 license text")
            require(b"Version 2.0" in data, f"{path} is not the Apache-2.0 license text")
            require(
                b"http://www.apache.org/licenses/" in data,
                f"{path} is not the Apache-2.0 license text",
            )
            require(
                b"END OF TERMS AND CONDITIONS" in data,
                f"{path} is not the complete Apache-2.0 license text",
            )
        elif path == MIT_LICENSE_PATH:
            require(is_authorized, f"{path} is only expected in the authorized inventory")
            require(artifact["license"] == "MIT", f"{label} license must be MIT")
            require(
                artifact["copyright"] == EXPECTED_COPYRIGHT_EMY,
                f"{label} copyright must be {EXPECTED_COPYRIGHT_EMY}",
            )
            require(b"MIT License" in data, f"{path} is not the MIT license text")
            require(
                b"Copyright (c) 2026 emyrinj" in data,
                f"{path} must carry the first-party MIT copyright",
            )
            require(
                b"Permission is hereby granted" in data,
                f"{path} is not the MIT license text",
            )
        elif path == NOTICE_PATH:
            require(is_authorized, f"{path} is only expected in the authorized inventory")
            text = decode_utf8(data, path)
            for marker in (
                "AstatineMiner",
                "AstatineGenesisCoordinator",
                "MockAST",
                "Apache-2.0",
                "MIT",
                "OPENZEPPELIN_LICENSE.txt",
                "LICENSE-APACHE-2.0.txt",
                "LICENSE-MIT.txt",
                "Copyright (c) 2026 emyrinj",
            ):
                require(marker in text, f"{path} NOTICE is missing required marker: {marker}")
            lowered_notice = text.lower()
            normalized_notice = " ".join(lowered_notice.split())
            require(
                "no separate" in normalized_notice and "upstream notice" in normalized_notice,
                f"{path} NOTICE must record the no-separate-upstream-NOTICE decision",
            )
            require(
                "not independently verified" in normalized_notice
                or "not been independently verified" in normalized_notice,
                f"{path} NOTICE must not claim independent verification",
            )
            require(
                "owner-attested" in normalized_notice or "owner attestation" in normalized_notice,
                f"{path} NOTICE must state ownership is owner-attested",
            )
            # L9 accurately scoped OpenZeppelin attribution: both trees reference
            # the pinned commit, MockAST imports one component, coordinator has
            # zero direct imports, retention is for applicable redistribution,
            # and no OZ code in every fixture (and none asserted for AstatineMiner).
            require(
                "pinned evm source trees reference" in normalized_notice,
                f"{path} NOTICE must scope both pinned EVM source trees referencing OpenZeppelin",
            )
            require(
                "dbb6104ce834628e473d2173bbc9d47f81a9eec3" in normalized_notice,
                f"{path} NOTICE must reference the pinned OpenZeppelin commit",
            )
            require(
                "imports one openzeppelin component" in normalized_notice,
                f"{path} NOTICE must state MockAST imports one OpenZeppelin component",
            )
            require(
                "zero direct openzeppelin imports" in normalized_notice,
                f"{path} NOTICE must state GenesisCoordinator has zero direct OpenZeppelin imports",
            )
            require(
                "for any fixture redistribution to which it applies" in normalized_notice,
                f"{path} NOTICE must retain the OZ notice for any applicable fixture redistribution",
            )
            require(
                "does not assert openzeppelin code in every fixture" in normalized_notice,
                f"{path} NOTICE must not assert OpenZeppelin code in every fixture",
            )
            require(
                "with any redistribution of mockast" not in normalized_notice
                and "included with mockast redistribution" not in normalized_notice,
                f"{path} NOTICE must not narrow OZ retention to MockAST-only redistribution",
            )
            # v3: technical review, no invented approver, no final-publication claim.
            require(
                "owner-authorized release intent" in normalized_notice,
                f"{path} NOTICE must state owner-authorized release intent",
            )
            require(
                "technical notice review" in normalized_notice or "technical review" in normalized_notice,
                f"{path} NOTICE must record repository technical review",
            )
            require(
                "not a legal conclusion" in normalized_notice,
                f"{path} NOTICE must state it is not a legal conclusion",
            )
            require(
                "final release controls" in normalized_notice and "outstanding" in normalized_notice,
                f"{path} NOTICE must state final release controls remain outstanding",
            )
            require(
                "project owner and release approver" not in normalized_notice,
                f"{path} NOTICE must not invent a release approver",
            )
            require(
                "publication authorized" not in normalized_notice
                and "publication authorization" not in normalized_notice,
                f"{path} NOTICE must not claim final publication authorization",
            )
        else:
            raise VerificationError(f"{label} has an unexpected legal artifact path: {path}")
        legal_by_path[path] = (artifact, data)
    require(len(set(legal_paths)) == len(legal_paths), "duplicate legal artifact paths")
    require(set(legal_paths) == expected_legal_paths, "legal artifact path inventory changed")
    if is_authorized:
        require(
            set(legal_paths) == EXPECTED_LEGAL_ARTIFACT_PATHS_V2,
            "authorized inventory must include the OpenZeppelin, Apache-2.0, MIT, and NOTICE legal artifacts",
        )
    else:
        require(
            set(legal_paths) == EXPECTED_LEGAL_ARTIFACT_PATHS_V1,
            "legal artifact path inventory changed",
        )

    openzeppelin = require_object(inventory.get("openzeppelin"), "openzeppelin")
    require_fields(
        openzeppelin,
        ("repository", "pinned_commit", "license", "copyright", "license_text", "verified", "evidence_scope"),
        "openzeppelin",
    )
    require_string(openzeppelin["repository"], "openzeppelin repository")
    require_git_sha1(openzeppelin["pinned_commit"], "openzeppelin pinned_commit")
    require(openzeppelin["pinned_commit"] == "dbb6104ce834628e473d2173bbc9d47f81a9eec3", "OZ pin changed")
    require_string(openzeppelin["license"], "openzeppelin license")
    require(openzeppelin["license"] == "MIT", "OZ license identity changed")
    require_string(openzeppelin["copyright"], "openzeppelin copyright")
    require(
        openzeppelin["copyright"] == "Copyright (c) 2016-2023 zOS Global Limited and contributors",
        "OZ copyright changed",
    )
    require_string(openzeppelin["license_text"], "openzeppelin license_text")
    require_bool(openzeppelin["verified"], "openzeppelin verified")
    require(openzeppelin["verified"] is True, "OZ evidence must be marked verified")
    require_string(openzeppelin["evidence_scope"], "openzeppelin evidence_scope")
    if is_authorized:
        _oz_scope = " ".join(openzeppelin["evidence_scope"].lower().split())
        require(
            "both pinned evm source trees reference" in _oz_scope,
            "openzeppelin evidence_scope must scope both pinned EVM source trees referencing OpenZeppelin",
        )
        require(
            "dbb6104ce834628e473d2173bbc9d47f81a9eec3" in _oz_scope,
            "openzeppelin evidence_scope must reference the pinned OpenZeppelin commit",
        )
        require(
            "imports one openzeppelin component" in _oz_scope,
            "openzeppelin evidence_scope must state MockAST imports one OpenZeppelin component",
        )
        require(
            "zero direct openzeppelin imports" in _oz_scope,
            "openzeppelin evidence_scope must state GenesisCoordinator has zero direct OpenZeppelin imports",
        )
        require(
            "for any fixture redistribution to which it applies" in _oz_scope,
            "openzeppelin evidence_scope must retain the OZ notice for any applicable fixture redistribution",
        )
        require(
            "does not assert openzeppelin code in every fixture" in _oz_scope,
            "openzeppelin evidence_scope must not assert OpenZeppelin code in every fixture",
        )
    require(
        openzeppelin["license_text"] == OPENZEPPELIN_LICENSE_PATH,
        "OZ license path must still point to tests/fixtures/OPENZEPPELIN_LICENSE.txt",
    )
    require(
        OPENZEPPELIN_LICENSE_PATH in legal_by_path,
        "OZ license path mismatch: OpenZeppelin license artifact is missing",
    )
    oz_artifact, _ = legal_by_path[OPENZEPPELIN_LICENSE_PATH]
    require(
        openzeppelin["license_text"] == oz_artifact["path"],
        "OZ license path mismatch",
    )

    rights = require_object(inventory.get("rights_review"), "rights_review")
    if is_authorized:
        require_fields(
            rights,
            (
                "first_party_license_identity",
                "copyright_evidence",
                "rights_holder_authority",
                "owner_attestation",
                "rights_decision",
                "notice_applicability",
                "notice_checklist",
                "not_inferred",
                "review_ci_branch_push_authorization",
                "release_intent_authorization",
            ),
            "rights_review",
        )
        require(
            "publication_decision" not in rights,
            "live v3 schema must not contain publication_decision; use rights_decision",
        )
        require(
            "publication_authorization" not in rights,
            "live v3 schema must not contain publication_authorization; use release_intent_authorization",
        )
    else:
        require_fields(
            rights,
            (
                "first_party_license_identity",
                "copyright_evidence",
                "rights_holder_authority",
                "owner_attestation",
                "notice_applicability",
                "notice_checklist",
                "publication_decision",
                "not_inferred",
            ),
            "rights_review",
        )
        require(
            "publication_authorization" not in rights,
            "blocked inventory must not contain publication_authorization",
        )
        require(
            "rights_decision" not in rights,
            "blocked inventory must not contain rights_decision",
        )
        require(
            "release_intent_authorization" not in rights,
            "blocked inventory must not contain release_intent_authorization",
        )
    for field in (
        "first_party_license_identity",
        "copyright_evidence",
        "not_inferred",
    ):
        require_string(rights[field], f"rights_review {field}")
    require_string(rights["rights_holder_authority"], "rights_review rights_holder_authority")
    require_string(rights["notice_applicability"], "rights_review notice_applicability")
    require(rights["rights_holder_authority"] == ATTESTED_RIGHTS, "rights status must remain honest")
    attestation = require_object(rights["owner_attestation"], "rights_review owner_attestation")
    require_fields(
        attestation,
        ("status", "scope", "attested_on", "attestation_source", "independent_verification"),
        "rights_review owner_attestation",
    )
    require_string(attestation["status"], "owner_attestation status")
    require_string(attestation["scope"], "owner_attestation scope")
    require_string(attestation["attested_on"], "owner_attestation attested_on")
    require_string(attestation["attestation_source"], "owner_attestation attestation_source")
    require_bool(attestation["independent_verification"], "owner_attestation independent_verification")
    require(attestation["status"] == ATTESTED_RIGHTS, "owner attestation status must match rights status")
    require(re.match(r"^\d{4}-\d{2}-\d{2}$", attestation["attested_on"]), "owner attestation date must be ISO 8601")
    require("first-party" in attestation["scope"].lower(), "owner attestation scope must identify first-party works")
    require(
        attestation["independent_verification"] is False,
        "owner attestation must not be represented as independent verification",
    )
    if is_authorized:
        lowered_scope = attestation["scope"].lower()
        require("astatineminer" in lowered_scope, "owner attestation scope must include AstatineMiner")
        require(
            "astatinegenesiscoordinator" in lowered_scope.replace(" ", "").replace("-", "").lower()
            or "genesis" in lowered_scope,
            "owner attestation scope must include AstatineGenesisCoordinator",
        )
        require("mockast" in lowered_scope, "owner attestation scope must include MockAST; missing MockAST authorization")
        require(
            attestation["attested_on"] == EXPECTED_RELEASE_INTENT_ON,
            "owner attestation date must be 2026-11-17 for the v3 inventory",
        )
        prior = attestation.get("prior_attestations")
        require(
            isinstance(prior, list) and len(prior) == 1,
            "owner attestation must preserve exactly one prior attestation",
        )
        require(
            prior[0] == EXPECTED_PRIOR_ATTESTATION,
            "owner attestation prior record changed; the 2026-11-15 Phase-D attestation must be preserved exactly",
        )
        source_lower = attestation["attestation_source"].lower()
        require(
            "2026-11-17" in attestation["attestation_source"],
            "owner attestation source must record the 2026-11-17 authorization",
        )
        require(
            "mockast" in source_lower,
            "owner attestation source must record MockAST authorization; missing MockAST authorization",
        )
        require(
            "authorized" in source_lower,
            "owner attestation source must record owner authorization",
        )
        require(
            "apache-2.0" in source_lower and "mit" in source_lower,
            "owner attestation source must record Apache-2.0 and MIT authorization",
        )
        require(
            "project owner and release approver" not in source_lower,
            "owner attestation source must not invent a release approver",
        )
        require(
            rights["rights_decision"] == EXPECTED_RIGHTS_DECISION_V3,
            "rights_decision must be the exact v3 owner-authorized release-intent contract",
        )
        require(
            rights["notice_applicability"] == EXPECTED_NOTICE_APPLICABILITY_V3,
            "NOTICE applicability must be the exact v3 technically-reviewed statement",
        )
    else:
        require(rights["notice_applicability"] == EXPECTED_NOTICE_APPLICABILITY, "NOTICE status must remain honest")
        require(
            rights["publication_decision"] == EXPECTED_PUBLICATION_DECISION,
            "publication decision changed; publication remains blocked",
        )
    push_auth = require_object(
        rights.get("review_ci_branch_push_authorization"),
        "rights_review review_ci_branch_push_authorization",
    )
    if is_authorized:
        require(
            push_auth.get("status") == EXPECTED_PUSH_STATUS_SUPERSEDED_V3,
            "review/CI branch push authorization must be SUPERSEDED \u2014 OWNER-AUTHORIZED RELEASE INTENT for v3",
        )
        require(
            push_auth.get("superseded_by") == EXPECTED_PUSH_SUPERSEDED_BY_V3,
            "superseded review/CI authorization must point to release_intent_authorization",
        )
        require(
            push_auth.get("superseded_on") == EXPECTED_PUSH_SUPERSEDED_ON,
            "superseded review/CI authorization date must be 2026-11-17",
        )
        require(
            push_auth.get("authorized_by") == "project owner",
            "review/CI branch push authorization author changed",
        )
        require(
            push_auth.get("authorized_on") == EXPECTED_REVIEW_PUSH_DATE,
            "review/CI branch push authorization date changed",
        )
        require(
            push_auth.get("scope") == EXPECTED_REVIEW_PUSH_SCOPE,
            "review/CI branch push authorization scope changed",
        )
        require(
            push_auth.get("public_repository_visibility") == EXPECTED_REVIEW_PUSH_VISIBILITY,
            "review/CI branch push visibility statement changed",
        )
        require(
            push_auth.get("not_authorized") == EXPECTED_REVIEW_PUSH_NOT_AUTHORIZED,
            "review/CI branch push blocked list changed; no item may be removed",
        )
        require(
            push_auth.get("rights_gate_unchanged") == EXPECTED_INTENT_REVIEW_PUSH_GATE,
            "review/CI branch push gate statement changed; the historical blocked state must be marked superseded",
        )
    else:
        require(
            push_auth.get("status") == EXPECTED_REVIEW_PUSH_STATUS,
            "review/CI branch push authorization status changed",
        )
        require(
            push_auth.get("authorized_by") == "project owner",
            "review/CI branch push authorization author changed",
        )
        require(
            push_auth.get("authorized_on") == EXPECTED_REVIEW_PUSH_DATE,
            "review/CI branch push authorization date changed",
        )
        require(
            push_auth.get("scope") == EXPECTED_REVIEW_PUSH_SCOPE,
            "review/CI branch push authorization scope changed",
        )
        require(
            push_auth.get("public_repository_visibility") == EXPECTED_REVIEW_PUSH_VISIBILITY,
            "review/CI branch push visibility statement changed",
        )
        require(
            push_auth.get("not_authorized") == EXPECTED_REVIEW_PUSH_NOT_AUTHORIZED,
            "review/CI branch push blocked list changed; no item may be removed",
        )
        require(
            push_auth.get("rights_gate_unchanged") == EXPECTED_REVIEW_PUSH_GATE_UNCHANGED,
            "review/CI branch push gate statement changed",
        )
        require(
            push_auth == EXPECTED_REVIEW_PUSH_AUTH,
            "review/CI branch push authorization changed",
        )

    if is_authorized:
        release_auth = require_object(
            rights.get("release_intent_authorization"),
            "rights_review release_intent_authorization",
        )
        require_fields(
            release_auth,
            ("status", "authorized_by", "authorized_on", "scope", "approval_roles", "evidence", "technical_notice_review", "final_release_controls_complete", "not_authorized", "independent_verification", "owner_self_approval", "independent_reviewer", "separation_of_duties"),
            "rights_review release_intent_authorization",
        )
        require(
            release_auth.get("status") == EXPECTED_RELEASE_INTENT_STATUS,
            "release_intent_authorization status must be OWNER-AUTHORIZED RELEASE INTENT \u2014 FINAL CONTROLS OUTSTANDING",
        )
        require(
            release_auth.get("authorized_by") == EXPECTED_RELEASE_INTENT_BY,
            "release_intent_authorization must be authorized by project owner only",
        )
        require(
            release_auth.get("authorized_on") == EXPECTED_RELEASE_INTENT_ON,
            "release_intent_authorization date must be 2026-11-17",
        )
        require(
            release_auth.get("scope") == EXPECTED_RELEASE_INTENT_SCOPE,
            "release_intent_authorization scope changed",
        )
        require(
            release_auth.get("approval_roles") == EXPECTED_RELEASE_INTENT_ROLES,
            "release_intent_authorization must state project owner only with no separate approver",
        )
        require_bool(release_auth.get("independent_verification"), "release_intent_authorization independent_verification")
        require(
            release_auth.get("independent_verification") is False,
            "release_intent_authorization must not claim independent verification",
        )
        require(
            release_auth.get("owner_self_approval") == EXPECTED_OWNER_SELF_APPROVAL_POLICY,
            "release_intent_authorization must record the explicit owner self-approval policy",
        )
        require(
            release_auth.get("independent_reviewer") is False,
            "release_intent_authorization must not claim an independent reviewer",
        )
        require(
            release_auth.get("separation_of_duties")
            == EXPECTED_OWNER_SELF_APPROVAL_POLICY["separation_of_duties"],
            "release_intent_authorization must not claim separation of duties",
        )
        require(
            rights.get("owner_self_approval") == EXPECTED_OWNER_SELF_APPROVAL_POLICY,
            "rights_review must record the explicit owner self-approval policy",
        )
        require(
            rights.get("historical_release_intent") == EXPECTED_HISTORICAL_RELEASE_INTENT,
            "rights_review must preserve the historical .1 release intent",
        )
        require(
            release_auth.get("final_release_controls_complete") is False,
            "final release controls must remain outstanding; must not claim complete",
        )
        evidence_list = require_list(release_auth.get("evidence"), "release_intent_authorization evidence")
        require(evidence_list, "release_intent_authorization evidence must not be empty")
        for value in evidence_list:
            require_string(value, "release_intent_authorization evidence entry")
        joined_evidence = "\n".join(evidence_list).lower()
        require("mockast" in joined_evidence, "release_intent_authorization evidence is missing MockAST authorization")
        require(
            "copyright (c) 2026 emyrinj" in joined_evidence or "emyrinj" in joined_evidence,
            "release_intent_authorization evidence must reference Apache-2.0 copyright emyrinj",
        )
        require("apache-2.0" in joined_evidence, "release_intent_authorization evidence must reference Apache-2.0")
        require(
            "tests/fixtures/license-apache-2.0.txt" in joined_evidence,
            "release_intent_authorization evidence must reference the Apache-2.0 license file",
        )
        require(
            "tests/fixtures/license-mit.txt" in joined_evidence,
            "release_intent_authorization evidence must reference the MIT license file",
        )
        require(
            "tests/fixtures/notice" in joined_evidence,
            "release_intent_authorization evidence must reference the fixture NOTICE",
        )
        require(
            "openzeppelin" in joined_evidence,
            "release_intent_authorization evidence must reference the retained OpenZeppelin MIT notice",
        )
        require(
            "release_archive_member" in joined_evidence
            or "excluded from binary" in joined_evidence
            or "remain excluded" in joined_evidence,
            "release_intent_authorization evidence must note fixtures remain excluded from binary archives",
        )
        require(
            "no legal conclusion" in joined_evidence,
            "release_intent_authorization evidence must state no legal conclusion",
        )
        require(
            "project owner and release approver" not in joined_evidence,
            "release_intent_authorization evidence must not invent a release approver",
        )
        require(
            "publication authorized" not in joined_evidence,
            "release_intent_authorization evidence must not claim final publication",
        )
        tech = require_object(release_auth.get("technical_notice_review"), "technical_notice_review")
        require_fields(
            tech,
            ("reviewed_on", "reviewed_by", "finding", "citations", "legal_conclusion", "separate_approval"),
            "technical_notice_review",
        )
        require(
            tech.get("reviewed_on") == EXPECTED_RELEASE_INTENT_ON,
            "technical_notice_review reviewed_on must be 2026-11-17",
        )
        require(
            tech.get("reviewed_by") == EXPECTED_TECHNICAL_REVIEWED_BY,
            "technical_notice_review reviewed_by must be repository technical review, not owner or separate approver",
        )
        require(
            tech.get("finding") == EXPECTED_TECHNICAL_FINDING,
            "technical_notice_review finding must be the exact evidence-based technical finding",
        )
        require(
            list(tech.get("citations", [])) == EXPECTED_TECHNICAL_CITATIONS,
            "technical_notice_review citations must list the six license/notice/provenance files",
        )
        require(
            tech.get("legal_conclusion") is False,
            "technical_notice_review must not claim a legal conclusion",
        )
        require(
            tech.get("separate_approval") is False,
            "technical_notice_review must not claim a separate approval",
        )
        not_auth_list = require_list(release_auth.get("not_authorized"), "release_intent_authorization not_authorized")
        require(not_auth_list, "release_intent_authorization not_authorized must not be empty")
        for value in not_auth_list:
            require_string(value, "release_intent_authorization not_authorized entry")
        joined_not = "\n".join(not_auth_list).lower()
        require(
            "other tag" in joined_not or "any other" in joined_not,
            "release_intent_authorization not_authorized must exclude any other tag/version",
        )
        require("mainnet" in joined_not, "release_intent_authorization not_authorized must exclude mainnet risk acceptance")
        require(
            "independent" in joined_not,
            "release_intent_authorization not_authorized must exclude independent legal verification",
        )
        require(
            "legal advice" in joined_not or "legal clearance" in joined_not or "legal conclusion" in joined_not,
            "release_intent_authorization not_authorized must exclude legal advice/clearance/conclusion",
        )
        require(
            "separate release approver" in joined_not,
            "release_intent_authorization not_authorized must exclude any separate approver assertion",
        )
        require(
            "protected environment" in joined_not,
            "release_intent_authorization not_authorized must require protected environment controls",
        )
        require(
            "writer" in joined_not,
            "release_intent_authorization not_authorized must require writer/app restriction",
        )
        require(
            "immutable" in joined_not,
            "release_intent_authorization not_authorized must require immutable verification/artifacts",
        )
        require(
            "attestation" in joined_not,
            "release_intent_authorization not_authorized must require attestations",
        )
        require(
            "bypass" in joined_not,
            "release_intent_authorization not_authorized must exclude bypass of controls",
        )
        require(
            "exact release tag" in joined_not or "exact tag" in joined_not,
            "release_intent_authorization not_authorized must require exact tag controls",
        )
        require(
            "main" in joined_not,
            "release_intent_authorization not_authorized must require main CI controls",
        )
    else:
        release_auth = None

    checklist = require_object(rights["notice_checklist"], "rights_review notice_checklist")
    require_fields(checklist, ("status", "scope", "items"), "rights_review notice_checklist")
    require_string(checklist["status"], "notice_checklist status")
    require_string(checklist["scope"], "notice_checklist scope")
    if is_authorized:
        require(
            checklist["status"] == EXPECTED_CHECKLIST_STATUS_V3,
            "notice checklist status must be TECHNICAL REVIEW RECORDED \u2014 owner-authorized release intent; final release controls outstanding",
        )
    else:
        require(
            checklist["status"] == EXPECTED_CHECKLIST_STATUS,
            "notice checklist status changed; the gate must stay exactly "
            "OPEN \u2014 publication remains BLOCKED",
        )
    items = require_list(checklist["items"], "notice_checklist items")
    require(items, "notice_checklist items must not be empty")
    item_ids = []
    blocking_open = 0
    blocking_open_ids: list[str] = []
    seen_blockers: set[str] = set()
    _EXPECTED_OWNERS_V3 = {
        "RIGHTS-01": "project owner",
        "RIGHTS-02": "repository technical review",
        "RIGHTS-03": "project owner",
        "RIGHTS-04": "project owner",
        "RIGHTS-05": "project owner",
    }
    _EXPECTED_EVIDENCE_SUBSTRINGS_V3 = {
        "RIGHTS-02": (
            "release_intent_authorization",
            "technical_notice_review",
            "tests/fixtures/license-apache-2.0.txt",
            "no separate upstream notice",
        ),
        "RIGHTS-03": (
            "release_intent_authorization",
            "technical_notice_review",
            "tests/fixtures/license-apache-2.0.txt",
            "copyright (c) 2026 emyrinj",
        ),
        "RIGHTS-04": (
            "release_intent_authorization",
            "technical_notice_review",
            "tests/fixtures/license-mit.txt",
            "for any fixture redistribution",
        ),
        "RIGHTS-05": (
            "release_intent_authorization",
            "technical_notice_review",
            "final release controls",
            "no legal conclusion",
        ),
    }
    for index, item in enumerate(items):
        label = f"notice_checklist items[{index}]"
        item = require_object(item, label)
        require_fields(item, ("id", "action", "owner", "status", "blocking", "evidence"), label)
        item_ids.append(require_string(item["id"], f"{label} id"))
        action = require_string(item["action"], f"{label} action")
        owner = require_string(item["owner"], f"{label} owner")
        item_status = require_string(item["status"], f"{label} status")
        require(item_status in {"OPEN", "DONE"}, f"{label} status is unknown: {item_status}")
        blocking = require_bool(item["blocking"], f"{label} blocking")
        evidence = require_string(item["evidence"], f"{label} evidence")
        if item_ids[-1] in EXPECTED_BLOCKER_DETAILS:
            expected_detail = EXPECTED_BLOCKER_DETAILS[item_ids[-1]]
            require(
                item_ids[-1] not in seen_blockers,
                f"notice_checklist contains duplicate blocking id: {item_ids[-1]}",
            )
            seen_blockers.add(item_ids[-1])
            require(
                blocking is True,
                f"rights gate item is not blocking: {item_ids[-1]}",
            )
            require(
                action == expected_detail["action"],
                f"rights gate item action changed: {item_ids[-1]}; rewording the "
                "checklist cannot imply approval",
            )
            if is_authorized:
                require(
                    owner == _EXPECTED_OWNERS_V3[item_ids[-1]],
                    f"rights gate item owner must be {_EXPECTED_OWNERS_V3[item_ids[-1]]} for v3: {item_ids[-1]}",
                )
                require(
                    item_status == "DONE",
                    f"rights gate blocking item is not DONE for v3: {item_ids[-1]}",
                )
                require(
                    evidence and evidence.strip(),
                    f"rights gate item DONE without evidence: {item_ids[-1]}",
                )
                for substring in _EXPECTED_EVIDENCE_SUBSTRINGS_V3[item_ids[-1]]:
                    require(
                        substring in evidence.lower(),
                        f"rights gate item evidence is missing required reference '{substring}': {item_ids[-1]}",
                    )
                require(
                    "project owner and release approver" not in evidence.lower(),
                    f"rights gate item evidence must not invent a release approver: {item_ids[-1]}",
                )
                require(
                    "publication authorized" not in evidence.lower()
                    and "publication_authorization" not in evidence.lower(),
                    f"rights gate item evidence must not claim final publication: {item_ids[-1]}",
                )
            else:
                require(
                    owner == expected_detail["owner"],
                    f"rights gate item owner changed: {item_ids[-1]}",
                )
                require(
                    item_status == "OPEN",
                    f"rights gate blocking item is not OPEN: {item_ids[-1]}",
                )
                require(
                    evidence == expected_detail["evidence"],
                    f"rights gate item evidence changed: {item_ids[-1]}",
                )
        if blocking and item_status == "OPEN":
            blocking_open += 1
            blocking_open_ids.append(item_ids[-1])
    require(len(set(item_ids)) == len(item_ids), "notice_checklist contains duplicate ids")
    require(
        seen_blockers == set(EXPECTED_BLOCKER_DETAILS),
        "rights gate is missing a blocking checklist item; expected "
        f"{sorted(EXPECTED_BLOCKER_DETAILS)}, got {sorted(seen_blockers)}",
    )
    if is_authorized:
        require(
            blocking_open == 0,
            "v3 inventory must have no open blocking checklist items",
        )
        # RIGHTS-01 owner must remain project owner for v3 as well
        for _id in item_ids:
            pass
        require(
            "RIGHTS-01" in item_ids,
            "v3 rights gate is missing RIGHTS-01",
        )
    else:
        require(
            blocking_open > 0,
            "publication is BLOCKED but no blocking notice-checklist item is open",
        )

    scrub = require_object(inventory.get("scrub_policy"), "scrub_policy")
    require_fields(
        scrub,
        (
            "scope",
            "prohibited_name_marker_sha256",
            "marker_check",
            "paths",
            "retained_private_origin_reference",
            "note",
        ),
        "scrub_policy",
    )
    require_string(scrub["scope"], "scrub_policy scope")
    require_string(scrub["marker_check"], "scrub_policy marker_check")
    require_string(scrub["note"], "scrub_policy note")
    markers = require_list(scrub["prohibited_name_marker_sha256"], "scrub marker digest list")
    require(markers, "scrub marker digest list is empty")
    for value in markers:
        require_sha256(value, "scrub marker digest")
    marker_set = set(markers)
    scrub_paths = require_list(scrub["paths"], "scrub path list")
    require(scrub_paths, "scrub path list is empty")
    expected_scrub_paths = EXPECTED_SCRUB_PATHS_V3 if is_authorized else EXPECTED_SCRUB_PATHS_V1
    checked_paths = []
    for index, relative in enumerate(scrub_paths):
        path = validate_relative_path(relative, f"scrub_policy paths[{index}]")
        require(path in expected_scrub_paths, f"scrub path is not expected: {path}")
        checked_paths.append(path)
    require(len(set(checked_paths)) == len(checked_paths), "duplicate scrub paths")
    require(set(checked_paths) == expected_scrub_paths, "scrub path inventory changed")
    retained = require_object(
        scrub["retained_private_origin_reference"], "scrub_policy retained_private_origin_reference"
    )
    require_fields(retained, ("path", "status", "reason"), "scrub_policy retained_private_origin_reference")
    retained_path = validate_relative_path(
        retained["path"], "retained_private_origin_reference path"
    )
    require(
        retained_path == "src/protocol.rs",
        "retained_private_origin_reference path changed",
    )
    require_string(retained["status"], "retained_private_origin_reference status")
    require_string(retained["reason"], "retained_private_origin_reference reason")
    if is_authorized:
        # R8: the test-module private-origin comment was genericized; no
        # production code changed. Blocked v1 retains the old status/reason.
        require(
            retained["status"] == "genericized",
            "retained_private_origin_reference status must be genericized for v3",
        )
        _retained_reason = " ".join(str(retained["reason"]).lower().split())
        require(
            "genericized" in _retained_reason,
            "retained_private_origin_reference reason must state the comment was genericized",
        )
        require(
            "test" in _retained_reason,
            "retained_private_origin_reference reason must reference the test-module comment",
        )
        require(
            "no production code" in _retained_reason,
            "retained_private_origin_reference reason must state no production code changed",
        )
        _scrub_note = " ".join(str(scrub["note"]).lower().split())
        require(
            "protocol" in _scrub_note and "test" in _scrub_note,
            "scrub note must cover source/protocol test comments for v3",
        )

    for relative in checked_paths:
        _, data = read_confined_bytes(root, relative, f"scrub path {relative}")
        text = decode_utf8(data, f"scrub document {relative}")
        for token in REPOSITORY_TOKEN.findall(text):
            digest = sha256_hex(token.lower().encode())
            require(digest not in marker_set, f"private-origin marker remains in {relative}")

    if is_authorized:
        # v3 README must reflect owner-authorized intent + technical review, with no invented approver.
        _, readme_data = read_confined_bytes(root, "tests/fixtures/README.md", "readme", EXPECTED_DOCUMENT_PATHS)
        readme_text = decode_utf8(readme_data, "tests/fixtures/README.md")
        _readme_norm = " ".join(readme_text.lower().split())
        require(
            "owner-authorized release intent" in _readme_norm,
            "fixture README must state owner-authorized release intent",
        )
        require(
            "technical" in _readme_norm and "notice" in _readme_norm,
            "fixture README must record technical NOTICE review",
        )
        require(
            "not a legal conclusion" in _readme_norm,
            "fixture README must state it is not a legal conclusion",
        )
        require(
            "final release controls" in _readme_norm and "outstanding" in _readme_norm,
            "fixture README must state final release controls remain outstanding",
        )
        require(
            "project owner and release approver" not in _readme_norm,
            "fixture README must not invent a release approver",
        )
        require(
            "publication authorized" not in _readme_norm
            and "publication_authorization" not in _readme_norm,
            "fixture README must not claim final publication authorization",
        )
        # Legal artifact NOTICE provenance/evidence must use technical wording for v3.
        _notice_prov = legal_by_path[NOTICE_PATH][0]
        _prov_norm = " ".join(str(_notice_prov.get("provenance", "")).lower().split())
        _evi_norm = " ".join(str(_notice_prov.get("evidence", "")).lower().split())
        require(
            "technical" in _prov_norm,
            "NOTICE provenance must reference technical NOTICE review",
        )
        require(
            "project owner and release approver" not in _prov_norm
            and "project owner and release approver" not in _evi_norm,
            "NOTICE provenance/evidence must not invent a release approver",
        )
        require(
            "publication authorized" not in _evi_norm
            and "publication_authorization" not in _evi_norm,
            "NOTICE evidence must not claim final publication",
        )

    if is_authorized:
        publication_authorized = False
        release_intent_authorized = True
        final_release_controls_complete = False
        authorization_status = release_auth["status"]
        blocking_open_list: list[str] = []
    else:
        publication_authorized = False
        release_intent_authorized = False
        final_release_controls_complete = False
        authorization_status = push_auth["status"]
        blocking_open_list = list(blocking_open_ids)
    if is_authorized:
        return {
            "schema": inventory["schema"],
            "fixtures_checked": len(entries),
            "documents_checked": len(documents),
            "legal_artifacts_checked": len(legal_artifacts),
            "scrub_paths_checked": len(scrub_paths),
            "openzeppelin_pin": openzeppelin["pinned_commit"],
            "openzeppelin_license": openzeppelin["license"],
            "rights_holder_authority": rights["rights_holder_authority"],
            "owner_attestation_status": attestation["status"],
            "owner_attestation_independent_verification": attestation["independent_verification"],
            "notice_applicability": rights["notice_applicability"],
            "notice_checklist_status": checklist["status"],
            "notice_checklist_items_checked": len(items),
            "notice_checklist_blocking_open": blocking_open,
            "blocking_open": blocking_open_list,
            "rights_decision": rights["rights_decision"],
            "review_ci_branch_push_authorization": push_auth["status"],
            "release_intent_authorization": release_auth["status"],
            "release_intent_authorized": release_intent_authorized,
            "publication_authorized": publication_authorized,
            "final_release_controls_complete": final_release_controls_complete,
            "authorization_status": authorization_status,
            "status": "PASS",
        }
    return {
        "schema": inventory["schema"],
        "fixtures_checked": len(entries),
        "documents_checked": len(documents),
        "legal_artifacts_checked": len(legal_artifacts),
        "scrub_paths_checked": len(scrub_paths),
        "openzeppelin_pin": openzeppelin["pinned_commit"],
        "openzeppelin_license": openzeppelin["license"],
        "rights_holder_authority": rights["rights_holder_authority"],
        "owner_attestation_status": attestation["status"],
        "owner_attestation_independent_verification": attestation["independent_verification"],
        "notice_applicability": rights["notice_applicability"],
        "notice_checklist_status": checklist["status"],
        "notice_checklist_items_checked": len(items),
        "notice_checklist_blocking_open": blocking_open,
        "blocking_open": blocking_open_list,
        "publication_decision": rights["publication_decision"],
        "review_ci_branch_push_authorization": push_auth["status"],
        "release_intent_authorized": release_intent_authorized,
        "publication_authorized": publication_authorized,
        "final_release_controls_complete": final_release_controls_complete,
        "authorization_status": authorization_status,
        "status": "PASS",
    }


def verify(root: Path) -> dict:
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as error:
        raise VerificationError(f"source root is not readable: {error}") from error
    require(resolved_root.is_dir(), f"source root is not a directory: {resolved_root}")
    try:
        return verify_inventory(resolved_root)
    except VerificationError:
        raise
    except OSError as error:
        raise VerificationError(f"filesystem error: {error}") from error
    except (KeyError, TypeError, ValueError, AttributeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"inventory/schema error: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=None,
        help="source root containing tests/fixtures/PROVENANCE.json (default: parent of support/)",
    )
    args = parser.parse_args()
    try:
        root = args.root if args.root is not None else Path(__file__).resolve().parents[1]
        result = verify(root)
    except VerificationError as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}, indent=2), file=sys.stderr)
        return 1
    except OSError as error:
        print(json.dumps({"status": "FAIL", "error": f"filesystem error: {error}"}, indent=2), file=sys.stderr)
        return 1
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        print(json.dumps({"status": "FAIL", "error": f"inventory/schema error: {error}"}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
