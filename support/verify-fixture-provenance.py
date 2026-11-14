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
EXPECTED_LEGAL_ARTIFACT_PATHS = frozenset({"tests/fixtures/OPENZEPPELIN_LICENSE.txt"})
EXPECTED_SCRUB_PATHS = frozenset(
    {
        "README.md",
        "MACOS_ARM64.md",
        "support/update-evm-test-fixtures.py",
        "support/update-genesis-coordinator-fixture.py",
        "tests/fixtures/README.md",
    }
)

ATTESTED_RIGHTS = "OWNER-ATTESTED — not independently verified"

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


def verify_inventory(root: Path) -> dict:
    _, inventory_bytes = read_confined_bytes(
        root, INVENTORY_PATH, "inventory", frozenset({INVENTORY_PATH})
    )
    inventory = parse_json_object(inventory_bytes, INVENTORY_PATH)
    require(inventory.get("schema") == "astatine-fixture-provenance/v1", "unexpected inventory schema")
    validate_inventory_metadata(inventory)

    entries = require_list(inventory.get("fixtures"), "fixtures")
    require(entries, "inventory has no fixtures")
    for index, entry in enumerate(entries):
        validate_fixture_entry(entry, index)
    entry_paths = [entry["path"] for entry in entries]
    require(len(set(entry_paths)) == len(entry_paths), "inventory contains duplicate fixture paths")
    require(set(entry_paths) == EXPECTED_FIXTURE_PATHS, "fixture path inventory changed")

    fixture_dir = root / FIXTURE_DIR
    require(fixture_dir.is_dir() and not fixture_dir.is_symlink(), "fixture directory is missing or a symlink")
    expected_names = {PurePosixPath(path).name for path in EXPECTED_FIXTURE_PATHS}
    actual_names: set[str] = set()
    try:
        with os.scandir(fixture_dir) as items:
            for item in items:
                require(not item.is_symlink(), f"fixture directory contains a symlink: {item.name}")
                is_regular = item.is_file(follow_symlinks=False)
                if not is_regular and item.name in expected_names:
                    raise VerificationError(f"fixture JSON entry must be a regular file: {item.name}")
                if (
                    is_regular
                    and item.name.endswith(".json")
                    and item.name != Path(INVENTORY_PATH).name
                ):
                    actual_names.add(item.name)
    except OSError as error:
        raise VerificationError(f"cannot scan fixture directory {FIXTURE_DIR}: {error}") from error
    require(actual_names == expected_names, "fixture JSON file set changed")

    for entry in entries:
        verify_fixture(root, entry)

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
    for index, artifact in enumerate(legal_artifacts):
        label = f"legal_artifacts[{index}]"
        artifact = require_object(artifact, label)
        require_fields(artifact, ("path", "sha256", "bytes", "license", "copyright", "provenance", "evidence"), label)
        path = validate_relative_path(artifact["path"], f"{label} path")
        require(path in EXPECTED_LEGAL_ARTIFACT_PATHS, f"{label} path is not expected: {path}")
        require_sha256(artifact["sha256"], f"{label} sha256")
        require_int(artifact["bytes"], f"{label} bytes")
        require_string(artifact["license"], f"{label} license")
        require_string(artifact["copyright"], f"{label} copyright")
        require_string(artifact["provenance"], f"{label} provenance")
        require_string(artifact["evidence"], f"{label} evidence")
        legal_paths.append(path)
        _, data = read_confined_bytes(root, path, label, EXPECTED_LEGAL_ARTIFACT_PATHS)
        require(len(data) == artifact["bytes"], f"{path} byte length changed")
        require(sha256_hex(data) == artifact["sha256"], f"{path} SHA-256 changed")
        require(b"The MIT License (MIT)" in data, f"{path} is not the MIT license text")
    require(len(set(legal_paths)) == len(legal_paths), "duplicate legal artifact paths")
    require(set(legal_paths) == EXPECTED_LEGAL_ARTIFACT_PATHS, "legal artifact path inventory changed")

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
    legal_artifact = legal_artifacts[0]
    require(openzeppelin["license_text"] == legal_artifact["path"], "OZ license path mismatch")

    rights = require_object(inventory.get("rights_review"), "rights_review")
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
    for field in (
        "first_party_license_identity",
        "copyright_evidence",
        "not_inferred",
    ):
        require_string(rights[field], f"rights_review {field}")
    require_string(rights["rights_holder_authority"], "rights_review rights_holder_authority")
    require_string(rights["notice_applicability"], "rights_review notice_applicability")
    require_string(rights["publication_decision"], "rights_review publication_decision")
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
    require(rights["notice_applicability"] == "UNRESOLVED", "NOTICE status must remain honest")
    require(rights["publication_decision"].startswith("BLOCKED"), "publication must remain blocked")

    checklist = require_object(rights["notice_checklist"], "rights_review notice_checklist")
    require_fields(checklist, ("status", "scope", "items"), "rights_review notice_checklist")
    require_string(checklist["status"], "notice_checklist status")
    require_string(checklist["scope"], "notice_checklist scope")
    require(checklist["status"].startswith("OPEN"), "notice checklist must stay open while publication is blocked")
    items = require_list(checklist["items"], "notice_checklist items")
    require(items, "notice_checklist items must not be empty")
    item_ids = []
    blocking_open = 0
    for index, item in enumerate(items):
        label = f"notice_checklist items[{index}]"
        item = require_object(item, label)
        require_fields(item, ("id", "action", "owner", "status", "blocking", "evidence"), label)
        item_ids.append(require_string(item["id"], f"{label} id"))
        require_string(item["action"], f"{label} action")
        require_string(item["owner"], f"{label} owner")
        item_status = require_string(item["status"], f"{label} status")
        require(item_status in {"OPEN", "DONE"}, f"{label} status is unknown: {item_status}")
        blocking = require_bool(item["blocking"], f"{label} blocking")
        require_string(item["evidence"], f"{label} evidence")
        if blocking and item_status == "OPEN":
            blocking_open += 1
    require(len(set(item_ids)) == len(item_ids), "notice_checklist contains duplicate ids")
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
    checked_paths = []
    for index, relative in enumerate(scrub_paths):
        path = validate_relative_path(relative, f"scrub_policy paths[{index}]")
        require(path in EXPECTED_SCRUB_PATHS, f"scrub path is not expected: {path}")
        checked_paths.append(path)
    require(len(set(checked_paths)) == len(checked_paths), "duplicate scrub paths")
    require(set(checked_paths) == EXPECTED_SCRUB_PATHS, "scrub path inventory changed")
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

    for relative in checked_paths:
        _, data = read_confined_bytes(root, relative, f"scrub path {relative}")
        text = decode_utf8(data, f"scrub document {relative}")
        for token in REPOSITORY_TOKEN.findall(text):
            digest = sha256_hex(token.lower().encode())
            require(digest not in marker_set, f"private-origin marker remains in {relative}")

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
        "notice_checklist_items_checked": len(items),
        "notice_checklist_blocking_open": blocking_open,
        "publication_decision": rights["publication_decision"],
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
