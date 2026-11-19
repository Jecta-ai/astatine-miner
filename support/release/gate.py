#!/usr/bin/env python3
"""Shared release-gate loader for distribution inventory and builders.

Offline, stdlib-only gate that validates both the blocked (v1) and the
authorized (v3) distribution states against the authoritative fixture
provenance. No network, build, wallet, mining, or publication operation
occurs here.

``load_gate(root, require_release_version=...)`` reads the canonical paths only
(``tests/fixtures/PROVENANCE.json`` and
``support/release/distribution-inventory.json``), validates the full shape,
cross-checks inventory against provenance, requires substantive license
evidence (actual license files with content markers and matching hashes),
and returns a normalized gate record.

Blocked state retains the exact canonical blocked constants so adversarial
tests using a blocked-shaped copy continue to fail closed. Authorized state
requires the exact owner/release-approver authorization, DONE checklist,
license/notice artifacts, pinned allowlists/targets, and external release
controls. Data-only authorization (flipping JSON strings without evidence,
files, or controls) fails.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import stat
from pathlib import Path, PurePosixPath

PROVENANCE_REL = "tests/fixtures/PROVENANCE.json"
INVENTORY_REL = "support/release/distribution-inventory.json"
CARGO_TOML_REL = "Cargo.toml"
EXPECTED_REGENERATION_SCRIPTS = {
    "FIX-01": "support/update-evm-test-fixtures.py",
    "FIX-02": "support/update-genesis-coordinator-fixture.py",
}
REPOSITORY_REL = "support/release-repository.txt"

# Current release identity. The owner self-approval model is version-scoped so
# an older tag cannot be dispatched under the new environment policy.
EXPECTED_RELEASE_VERSION = "0.1.0-testnet.6"
EXPECTED_RELEASE_TAG = "v0.1.0-testnet.6"
EXPECTED_RELEASE_TAG_POLICY = f"refs/tags/{EXPECTED_RELEASE_TAG}"
# Both composable tag rulesets preserve the live breadth: exactly refs/tags/v*
# with no exclusions. Narrowing to the single .6 tag or the historical
# .0/.1/.2/.3/.4/.5 list would weaken protection for all other v* tags.
EXPECTED_TAG_RULESET_SCOPE = "refs/tags/v*"
EXPECTED_TAG_IMMUTABILITY_SCOPE = ["refs/tags/v*"]
EXPECTED_RELEASE_REVIEWER_ID = 86115037
EXPECTED_RELEASE_REVIEWER_LOGIN = "emyrinj"
EXPECTED_RELEASE_TAG_CREATION_RULESET_NAME = "astatine-release-tag-creation"
EXPECTED_RELEASE_TAG_IMMUTABILITY_RULESET_NAME = "astatine-release-tags"
EXPECTED_RELEASE_TAG_CREATION_BYPASS_ACTORS = [
    {
        "actor_id": EXPECTED_RELEASE_REVIEWER_ID,
        "actor_type": "User",
        "bypass_mode": "always",
    },
]

# Historical .1 release intent. The substantive .1 fields are retained
# verbatim so the current .6 authorization cannot rewrite or silently erase
# what was recorded for .1.
HISTORICAL_RELEASE_TAG = "v0.1.0-testnet.1"
HISTORICAL_RELEASE_COMMIT = "99a8630a7ae7f5c5950031dfba8c3b0c3f132cbc"
HISTORICAL_RELEASE_NOTES_REL = "support/release/RELEASE_NOTES-v0.1.0-testnet.1.md"
HISTORICAL_RELEASE_NOTES_SHA256 = "12d7605b5e48c80f1c838a95d245c08da8cd5c831d008da3bb3dea420bdc31b9"
RELEASE_NOTES_REL = "support/release/RELEASE_NOTES-v0.1.0-testnet.6.md"
RELEASE_NOTES_SHA256 = "9f680d548a5b481e7401e6fb69f6039a535d68ca7a3c81fc45f0c80bf6136d80"
HISTORICAL_RIGHTS_DECISION = (
    "OWNER-AUTHORIZED RELEASE INTENT \u2014 project owner authorized first-party "
    "source and binary distribution intent for v0.1.0-testnet.1; technical "
    "NOTICE review recorded; final release controls outstanding; not a legal "
    "conclusion or separate approval."
)
HISTORICAL_RELEASE_INTENT_SCOPE = (
    "Owner-authorized first-party source and binary distribution intent "
    "for v0.1.0-testnet.1 on macOS ARM64 and Linux x86_64; final release "
    "controls remain outstanding."
)
HISTORICAL_APPROVAL_ROLES = (
    "Project owner only; no separate release approver was appointed, "
    "consulted, or asserted."
)
HISTORICAL_RELEASE_STATUS = (
    "SUPERSEDED \u2014 UNPUBLISHED; historical tag and pending draft workflow "
    "retained; no publication occurred"
)

# ---------------------------------------------------------------------------
# Blocked (v1) canonical constants — retained for backward-compatible
# adversarial tests. Any deviation from these fails closed.
# ---------------------------------------------------------------------------

BLOCKED_INVENTORY_SCHEMA = "astatine-distribution-inventory/v1"
BLOCKED_PROVENANCE_SCHEMA = "astatine-fixture-provenance/v1"
BLOCKED_PUBLICATION_DECISION = (
    "BLOCKED pending review of rights and notice applicability; "
    "first-party ownership is owner-attested and not independently verified."
)
BLOCKED_NOTICE_APPLICABILITY = "UNRESOLVED"
BLOCKED_CHECKLIST_STATUS = "OPEN \u2014 publication remains BLOCKED"
BLOCKED_BLOCKING_OPEN = ["RIGHTS-02", "RIGHTS-03", "RIGHTS-04", "RIGHTS-05"]
BLOCKED_BLOCKING_OPEN_SET = frozenset(BLOCKED_BLOCKING_OPEN)
BLOCKED_TARGET = "x86_64-unknown-linux-gnu"
BLOCKED_ARCHIVE_MEMBERS = (
    ("target/release/astatine", "astatine"),
    ("LICENSE-MIT", "LICENSE-MIT"),
    ("THIRD_PARTY_LICENSES.md", "THIRD_PARTY_LICENSES.md"),
)
BLOCKED_GENERATOR = "support/release/build-dry-run.py"
BLOCKED_GENERATED_MEMBERS = (
    ("BUILD-INFO.json", BLOCKED_GENERATOR),
    ("INSTALL.md", BLOCKED_GENERATOR),
)
BLOCKED_REVIEW_PUSH_AUTH = {
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
INTENT_REVIEW_PUSH_GATE = (
    "As of 2026-11-16, superseded 2026-11-17: RIGHTS-02 through RIGHTS-05 were OPEN and blocking; "
    "source_distribution and binary_distribution were BLOCKED."
)
BLOCKED_BLOCKER_DETAILS = {
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

# ---------------------------------------------------------------------------
# Authorized (v3) canonical constants.
# ---------------------------------------------------------------------------

INTENT_INVENTORY_SCHEMA = "astatine-distribution-inventory/v3"
INTENT_PROVENANCE_SCHEMA = "astatine-fixture-provenance/v3"
INTENT_RIGHTS_DECISION = (
    "OWNER-AUTHORIZED RELEASE INTENT \u2014 project owner authorized first-party "
    "source and binary distribution intent for v0.1.0-testnet.6 under the "
    "explicitly documented owner self-approval policy; technical NOTICE review "
    "recorded; final release controls outstanding; not a legal conclusion, not "
    "independent review, and not a separate approval."
)
INTENT_NOTICE_APPLICABILITY = (
    "TECHNICALLY REVIEWED \u2014 no separate upstream NOTICE file was found in "
    "the pinned contract fixture subtrees; the private EVM root NOTICE is "
    "scoped to a separate Rust subtree; Apache-2.0 license text and fixture "
    "NOTICE are included. This is an evidence-based technical review, not a "
    "legal conclusion or separate approval."
)
INTENT_CHECKLIST_STATUS = (
    "TECHNICAL REVIEW RECORDED \u2014 owner-authorized release intent under "
    "the explicit owner self-approval policy; final release controls outstanding"
)
AUTHORIZED_TARGETS = ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"]
AUTHORIZED_ARCHIVE_MEMBERS = (
    ("target/release/astatine", "astatine"),
    ("target/release/astatine.exe", "astatine.exe"),
    ("LICENSE-MIT", "LICENSE-MIT"),
    ("THIRD_PARTY_LICENSES.md", "THIRD_PARTY_LICENSES.md"),
)
AUTHORIZED_GENERATOR = "support/release/build-release.py"
AUTHORIZED_GENERATED_MEMBERS = (
    ("BUILD-INFO.json", AUTHORIZED_GENERATOR),
    ("INSTALL.md", AUTHORIZED_GENERATOR),
)
AUTHORIZED_FIXTURE_PATHS = frozenset(
    {
        "tests/fixtures/AstatineMiner.json",
        "tests/fixtures/AstatineGenesisCoordinator.json",
        "tests/fixtures/MockAST.json",
        "tests/fixtures/synthetic-injective-virtual-receipt.json",
    }
)
AUTHORIZED_LEGAL_ARTIFACT_PATHS = frozenset(
    {
        "tests/fixtures/OPENZEPPELIN_LICENSE.txt",
        "tests/fixtures/LICENSE-APACHE-2.0.txt",
        "tests/fixtures/LICENSE-MIT.txt",
        "tests/fixtures/NOTICE",
    }
)
REQUIRED_FORBIDDEN_GLOBS = frozenset({"tests/fixtures/**", "**/PROVENANCE.json"})
ATTESTED_RIGHTS = "OWNER-ATTESTED \u2014 not independently verified"
EXPECTED_REPOSITORY = "Jecta-ai/astatine-miner"
EXPECTED_PACKAGE_NAME = "astatine-cli-rust"

INTENT_RELEASE_INTENT_STATUS = (
    "OWNER-AUTHORIZED RELEASE INTENT \u2014 FINAL CONTROLS OUTSTANDING \u2014 "
    "OWNER SELF-APPROVAL"
)
INTENT_AUTHORIZED_BY = "project owner"
INTENT_AUTHORIZED_ON = "2026-11-17"
INTENT_SCOPE = (
    "Owner-authorized first-party source and binary distribution intent for "
    "v0.1.0-testnet.6 on macOS ARM64, Linux x86_64, and Windows x86_64 under an explicit owner "
    "self-approval policy; no independent reviewer or separate approver; final "
    "release controls remain outstanding."
)
INTENT_APPROVAL_ROLES = (
    "Project owner only; the owner explicitly authorized owner self-approval "
    "for the protected release environment. No independent reviewer and no "
    "separate release approver was appointed, consulted, or asserted; "
    "separation of duties is explicitly reduced and recorded as a security "
    "tradeoff."
)
INTENT_TECHNICAL_REVIEWED_BY = (
    "Repository technical review; not the project owner and not a separate "
    "release approver."
)
INTENT_TECHNICAL_REVIEWED_ON = "2026-11-17"

INTENT_INVENTORY_SCOPE = (
    "Candidate source and binary distribution inventory for Astatine "
    "v0.1.0-testnet.6 on macOS ARM64, Linux x86_64, and Windows x86_64. Owner-authorized release "
    "intent under an explicitly documented owner self-approval policy with "
    "technical NOTICE review recorded (citations included); final release "
    "controls remain outstanding; licensing is owner-authorized, release "
    "execution remains externally gated draft-only and is not established by "
    "this file."
)
INTENT_RULE = (
    "Distribution intent is owner-authorized only with substantive technical "
    "NOTICE review (citations), license evidence (Apache-2.0 and MIT texts, "
    "fixture NOTICE, fixture license records), pinned allowlists/targets, an "
    "explicitly recorded owner self-approval policy that does not claim "
    "independent review, and external draft-only release controls with final "
    "release controls outstanding; data-only JSON edits without that evidence "
    "and controls cannot authorize release intent. A PASS only confirms the "
    "release-intent inventory is truthfully recorded and technically reviewed; "
    "it does not authorize final publication, establish external environment, "
    "tag, or CI controls, or claim legal conclusion, independent review, or "
    "separate approval, which remain outstanding and are enforced by the "
    "release workflow and owner manual publication."
)
INTENT_SOURCE_REASON = (
    "Source distribution intent is owner-authorized (RELEASE-INTENT-AUTHORIZED) "
    "for v0.1.0-testnet.6 only under the owner self-approval policy: "
    "GitHub-generated source archives for the exact tag include tests/fixtures "
    "and the Apache-2.0/MIT license texts and fixture NOTICE; final release "
    "controls remain outstanding (final_release_controls_complete: false); "
    "execution still requires external draft-only release controls."
)
INTENT_BINARY_REASON = (
    "Binary distribution intent is owner-authorized (RELEASE-INTENT-AUTHORIZED) "
    "for v0.1.0-testnet.6 on macOS ARM64, Linux x86_64, and Windows x86_64 only under the owner "
    "self-approval policy: pinned allowlist archives plus generated "
    "BUILD-INFO.json and INSTALL.md; no fixture, provenance, or forbidden path "
    "may enter a release archive; final release controls remain outstanding "
    "(final_release_controls_complete: false); execution still requires "
    "external draft-only release controls."
)
INTENT_REVIEW_STATUS = "SUPERSEDED \u2014 OWNER-AUTHORIZED RELEASE INTENT"
INTENT_REVIEW_SUPERSEDED_BY = "release_intent_authorization"
INTENT_REVIEW_SUPERSEDED_ON = "2026-11-17"

RELEASE_IDENTITY = {
    "version": EXPECTED_RELEASE_VERSION,
    "tag": EXPECTED_RELEASE_TAG,
    "tag_policy": EXPECTED_RELEASE_TAG_POLICY,
    "exact_tag_required": True,
}

OWNER_SELF_APPROVAL_POLICY = {
    "status": "ACTIVE \u2014 OWNER SELF-APPROVAL",
    "approved_by": "project owner",
    "approved_on": "2026-11-17",
    "authorization_source": (
        "Project owner directive in the release implementation task: sustainable "
        "owner-controlled release without any external human reviewer; the owner "
        "expressly authorized the new version and the owner "
        "self-approval model."
    ),
    "scope": (
        "The owner account emyrinj (immutable numeric GitHub user id 86115037) "
        "is the sole required reviewer for the protected release environment and "
        "may approve a deployment initiated by the same account. The owner also "
        "manually publishes the verified draft."
    ),
    "independent_reviewer": False,
    "separation_of_duties": (
        "NONE \u2014 the same owner account initiates the workflow, approves the "
        "protected environment, and performs manual publication; no independent "
        "human approval is required or claimed."
    ),
    "security_tradeoff": (
        "Removes independent separation of duties and a second-person review. A "
        "compromised, malicious, or mistaken owner account can approve and "
        "publish without another human check."
    ),
    "residual_risk_accepted": True,
    "owner_attested": True,
    "independent_verification": False,
    "compensating_controls": [
        "exact release tag pinned to v0.1.0-testnet.6 and an exact-tag environment deployment policy",
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

HISTORICAL_RELEASE_INTENT = {
    "tag": HISTORICAL_RELEASE_TAG,
    "commit": HISTORICAL_RELEASE_COMMIT,
    "status": HISTORICAL_RELEASE_STATUS,
    "rights_decision": HISTORICAL_RIGHTS_DECISION,
    "scope": HISTORICAL_RELEASE_INTENT_SCOPE,
    "approval_roles": HISTORICAL_APPROVAL_ROLES,
    "release_notes_path": HISTORICAL_RELEASE_NOTES_REL,
    "release_notes_sha256": HISTORICAL_RELEASE_NOTES_SHA256,
    "note": (
        "The .1 rights decision, scope and approval roles are preserved "
        "verbatim; the tag, commit, release-notes hash and status metadata are "
        "added to identify the historical record. The .1 tag is not moved; its "
        "workflow run is not cancelled or deleted; no .1 release was published. "
        "The current .6 authorization does not alter the preserved .1 fields."
    ),
}

AUTHORIZED_RELEASE_CONTROLS = {
    "status": "DRAFT-ONLY \u2014 OWNER SELF-APPROVAL AFTER IMMUTABLE TAG/RELEASE VERIFICATION",
    "workflow": ".github/workflows/release.yml",
    "environment": "release",
    "environment_required_reviewer": True,
    "environment_prevent_self_review": False,
    "environment_reviewer_owner_id": EXPECTED_RELEASE_REVIEWER_ID,
    "environment_reviewer_owner_login": EXPECTED_RELEASE_REVIEWER_LOGIN,
    "independent_environment_review": False,
    "owner_self_approval": True,
    "publication_mode": "draft-only-manual-publish",
    "manual_publish_required": True,
    "final_release_controls_complete": False,
    "tag_policy": EXPECTED_RELEASE_TAG_POLICY,
    "exact_tag_required": True,
    "tag_ruleset_exact_scope": EXPECTED_TAG_RULESET_SCOPE,
    "immutable_release": True,
    "immutable_tag_required": True,
    "tag_creation_ruleset_name": EXPECTED_RELEASE_TAG_CREATION_RULESET_NAME,
    "tag_creation_rule_required": True,
    "tag_creation_bypass_actors_allowed": [dict(actor) for actor in EXPECTED_RELEASE_TAG_CREATION_BYPASS_ACTORS],
    "tag_immutability_ruleset_name": EXPECTED_RELEASE_TAG_IMMUTABILITY_RULESET_NAME,
    "tag_immutability_scope": list(EXPECTED_TAG_IMMUTABILITY_SCOPE),
    "tag_immutability_bypass_actors_allowed": 0,
    "immutable_setting_admin_verification_required": True,
    "attestations": ["build-provenance"],
    "exact_tag_main_ci": True,
    "external_blockers": [
        "protected release environment requires the owner reviewer (immutable numeric GitHub user id 86115037) with prevent_self_review false and administrator bypass disabled",
        "exact tag v0.1.0-testnet.6 for the exact release commit, with the environment deployment policy restricted to that exact tag",
        "separate active astatine-release-tag-creation ruleset restricted to exactly refs/tags/v* with no exclusions and with exactly the owner-user (User 86115037, always) creation bypass; repository-admin bypass is rejected",
        "separate active astatine-release-tags ruleset limited to update, deletion and non-fast-forward for exactly refs/tags/v* with no exclusions and with zero bypass actors",
        "tag creation protection is retained; no broader bypass or removal of the creation rule is authorized",
        "green exact-commit main CI for Rust CI and Linux native qualification",
        "owner/admin verifies immutable releases are enabled before dispatch and again immediately before manual publication",
        "repository writers and write-capable apps are restricted so only the release owner/admin can publish or modify the draft",
        "release tag and draft assets are rechecked immediately before manual publication",
        "owner self-approval reduces separation of duties; no independent review is claimed",
    ],
    "offline_verification": (
        "Offline verification cannot establish GitHub environment protection, "
        "the split tag creation/immutability ruleset bypass settings, tag "
        "existence, CI status, or the immutable-release repository setting; "
        "these are enforced by the release workflow preflight, build jobs, and "
        "owner manual publication steps before any publication."
    ),
}

# Release-intent checklist: actions stay the blocked canonical text and owners
# are the v3-recorded owners (RIGHTS-02 reviewed by repository technical
# review); every item is DONE with substantive recorded evidence. Evidence
# text is required non-empty but not byte-exact so wording updates do not
# falsely fail; exactness is enforced on decisions, statuses, owners, and
# the mirrored authorization objects.
INTENT_CHECKLIST_OWNERS = {
    "RIGHTS-01": "project owner",
    "RIGHTS-02": "repository technical review",
    "RIGHTS-03": "project owner",
    "RIGHTS-04": "project owner",
    "RIGHTS-05": "project owner",
}
INTENT_RIGHTS_01_ACTION = "Record the project owner's confirmation of first-party ownership of AstatineMiner and AstatineGenesisCoordinator."


class GateError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def require_object(value: object, label: str) -> dict:
    require(isinstance(value, dict), f"{label} must be an object")
    return value  # type: ignore[return-value]


def require_list(value: object, label: str) -> list:
    require(isinstance(value, list), f"{label} must be a list")
    return value  # type: ignore[return-value]


def require_string(value: object, label: str) -> str:
    require(isinstance(value, str) and value, f"{label} must be a non-empty string")
    return value  # type: ignore[return-value]


def require_bool(value: object, label: str) -> bool:
    require(isinstance(value, bool), f"{label} must be a boolean")
    return value  # type: ignore[return-value]


def validate_relative_path(value: object, label: str) -> str:
    require(
        isinstance(value, str) and value,
        f"{label} must be a non-empty relative path string",
    )
    require("\x00" not in value, f"{label} must not contain NUL")  # type: ignore[operator]
    require("\\" not in value, f"{label} must not contain backslash: {value}")  # type: ignore[operator]
    path = PurePosixPath(value)  # type: ignore[arg-type]
    require(not path.is_absolute(), f"{label} must not be absolute: {value}")
    parts = path.parts
    require(
        parts and all(part not in ("", ".", "..") for part in parts),
        f"{label} contains traversal: {value}",
    )
    require(path.as_posix() == value, f"{label} is not a canonical relative path: {value}")
    return value  # type: ignore[return-value]


def validate_glob(value: object, label: str) -> str:
    require(isinstance(value, str) and value, f"{label} must be a non-empty string")
    require("\x00" not in value, f"{label} must not contain NUL")  # type: ignore[operator]
    require("\\" not in value, f"{label} must not contain backslash: {value}")  # type: ignore[operator]
    require(not value.startswith("/"), f"{label} must not be absolute: {value}")  # type: ignore[union-attr]
    for part in PurePosixPath(value).parts:  # type: ignore[arg-type]
        require(part != "..", f"{label} contains traversal: {value}")
    return value  # type: ignore[return-value]


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


def read_confined_bytes(root: Path, relative: str, label: str) -> bytes:
    validate_relative_path(relative, f"{label} path")
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        try:
            status = current.lstat()
        except OSError as error:
            raise GateError(f"cannot read {label} {relative}") from error
        require(
            not stat.S_ISLNK(status.st_mode),
            f"{label} path contains a symlink component: {relative}",
        )
    require(stat.S_ISREG(status.st_mode), f"{label} must be a regular file: {relative}")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise GateError(f"{label} escapes the source root: {relative}") from error
    try:
        return current.read_bytes()
    except OSError as error:
        raise GateError(f"cannot read {label} {relative}") from error


def parse_json_object(data: bytes, label: str) -> dict:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GateError(f"{label} is not valid UTF-8: {error}") from error
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise GateError(f"invalid JSON in {label}: {error}") from error
    require(isinstance(value, dict), f"{label} must contain a JSON object")
    return value


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


def _check_archive_sets(
    binary: dict,
    expected_members: tuple[tuple[str, str], ...],
    expected_generated: tuple[tuple[str, str], ...],
    expected_target_label: str,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[str], list[str]]:
    members = require_list(binary.get("archive_members"), "binary_distribution archive_members")
    require(members, "binary_distribution archive_members must not be empty")
    seen_sources: set[str] = set()
    seen_archives: set[str] = set()
    member_pairs: list[tuple[str, str]] = []
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
        set(member_pairs) == set(expected_members),
        f"binary_distribution archive_members changed; {expected_target_label}",
    )
    require(
        len(member_pairs) == len(expected_members),
        "binary_distribution archive_members must list exactly the allowlisted members",
    )

    generated = require_list(binary.get("generated_members"), "binary_distribution generated_members")
    require(generated, "binary_distribution generated_members must not be empty")
    generated_pairs: list[tuple[str, str]] = []
    seen_generated: set[str] = set()
    for index, member in enumerate(generated):
        label = f"binary_distribution generated_members[{index}]"
        member = require_object(member, label)
        archive_path = validate_relative_path(member.get("archive_path"), f"{label} archive_path")
        generator = require_string(member.get("generator"), f"{label} generator")
        require(member.get("required") is True, f"{label} required must be true")
        require(
            archive_path not in seen_generated,
            f"{label} duplicate generated member archive_path: {archive_path}",
        )
        seen_generated.add(archive_path)
        generated_pairs.append((archive_path, generator))
        require(
            archive_path not in seen_archives,
            f"{label} overlaps a source archive member path: {archive_path}",
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
    fixture_strings = [validate_relative_path(p, f"binary_distribution fixture_paths[{i}]") for i, p in enumerate(fixture_paths)]
    require(
        len(set(fixture_strings)) == len(fixture_strings),
        "binary_distribution fixture_paths contains duplicates",
    )

    # Fail closed before allowlist comparison so smuggled fixtures or
    # forbidden paths are reported as archive-exclusion violations.
    for index, (source, archive_path) in enumerate(member_pairs):
        label = f"binary_distribution archive_members[{index}]"
        for fixture in fixture_strings:
            require(
                source != fixture and archive_path != fixture,
                f"{label} allows a fixture into the release archive: {fixture}",
            )
        for pattern in forbidden_strings:
            require(
                not glob_matches(source, pattern),
                f"{label} source is allowed by a forbidden glob into the release archive: {source} matches {pattern}",
            )
            require(
                not glob_matches(archive_path, pattern),
                f"{label} archive_path is allowed by a forbidden glob into the release archive: {archive_path} matches {pattern}",
            )
    for index, (archive_path, _generator) in enumerate(generated_pairs):
        label = f"binary_distribution generated_members[{index}]"
        for fixture in fixture_strings:
            require(
                archive_path != fixture,
                f"{label} allows a fixture into the release archive: {fixture}",
            )
        for pattern in forbidden_strings:
            require(
                not glob_matches(archive_path, pattern),
                f"{label} archive_path is allowed by a forbidden glob into the release archive: {archive_path} matches {pattern}",
            )
    return member_pairs, generated_pairs, forbidden_strings, fixture_strings


def _validate_blocked(
    root: Path, provenance: dict, inventory: dict
) -> dict:
    require(
        inventory.get("schema") == BLOCKED_INVENTORY_SCHEMA,
        f"unexpected distribution inventory schema: {inventory.get('schema')!r}",
    )
    require(
        provenance.get("schema") == BLOCKED_PROVENANCE_SCHEMA,
        f"unexpected fixture provenance schema: {provenance.get('schema')!r}",
    )
    require_string(inventory.get("scope"), "distribution inventory scope")
    gate = require_object(inventory.get("rights_gate"), "rights_gate")
    require(gate.get("source") == PROVENANCE_REL, "rights_gate source changed")
    gate_decision = require_string(gate.get("publication_decision"), "rights_gate publication_decision")
    gate_notice = require_string(gate.get("notice_applicability"), "rights_gate notice_applicability")
    blocking_open = require_list(gate.get("blocking_open"), "rights_gate blocking_open")
    require(
        all(isinstance(item, str) and item for item in blocking_open),
        "rights_gate blocking_open must be a list of non-empty strings",
    )
    require(
        list(blocking_open) == list(BLOCKED_BLOCKING_OPEN),
        "rights_gate blocking_open changed",
    )
    require(gate.get("fail_closed") is True, "rights_gate fail_closed must be true")
    require_string(gate.get("rule"), "rights_gate rule")
    gate_push = require_object(gate.get("review_ci_branch_push_authorization"), "rights_gate review_ci_branch_push_authorization")
    require(
        gate_push == BLOCKED_REVIEW_PUSH_AUTH,
        "rights_gate review/CI branch push authorization changed",
    )
    source_dist = require_object(inventory.get("source_distribution"), "source_distribution")
    require(source_dist.get("status") == "BLOCKED", "source distribution must remain BLOCKED")
    require_string(source_dist.get("reason"), "source_distribution reason")
    binary = require_object(inventory.get("binary_distribution"), "binary_distribution")
    require(binary.get("status") == "BLOCKED", "binary distribution must remain BLOCKED")
    require_string(binary.get("reason"), "binary_distribution reason")
    require(binary.get("target") == BLOCKED_TARGET, f"binary_distribution target changed: {binary.get('target')!r}")
    member_pairs, generated_pairs, forbidden_strings, fixture_strings = _check_archive_sets(
        binary, BLOCKED_ARCHIVE_MEMBERS, BLOCKED_GENERATED_MEMBERS, "blocked allowlist"
    )
    require(
        generated_pairs == list(BLOCKED_GENERATED_MEMBERS),
        "binary_distribution generated_members changed",
    )
    # Cross-check against provenance.
    rights = require_object(provenance.get("rights_review"), "rights_review")
    provenance_decision = require_string(rights.get("publication_decision"), "rights_review publication_decision")
    provenance_notice = require_string(rights.get("notice_applicability"), "rights_review notice_applicability")
    require(provenance_decision == BLOCKED_PUBLICATION_DECISION, "rights gate publication decision changed")
    require(provenance_notice == BLOCKED_NOTICE_APPLICABILITY, "NOTICE applicability must remain UNRESOLVED")
    require(
        rights.get("rights_holder_authority") == ATTESTED_RIGHTS,
        "rights status must remain honest",
    )
    attestation = require_object(rights.get("owner_attestation"), "rights_review owner_attestation")
    require(attestation.get("status") == ATTESTED_RIGHTS, "owner attestation status must remain honest")
    require(attestation.get("independent_verification") is False, "owner attestation must not be represented as independent verification")
    require(gate_decision == provenance_decision, "inventory publication_decision does not match tests/fixtures/PROVENANCE.json")
    require(gate_notice == provenance_notice, "inventory notice_applicability does not match tests/fixtures/PROVENANCE.json")
    provenance_push = require_object(rights.get("review_ci_branch_push_authorization"), "rights_review review_ci_branch_push_authorization")
    require(provenance_push == BLOCKED_REVIEW_PUSH_AUTH, "PROVENANCE.json review/CI branch push authorization changed")
    require(gate_push == provenance_push, "inventory review/CI branch push authorization does not match tests/fixtures/PROVENANCE.json")
    checklist = require_object(rights.get("notice_checklist"), "rights_review notice_checklist")
    require(require_string(checklist.get("status"), "notice_checklist status") == BLOCKED_CHECKLIST_STATUS, "notice checklist status changed")
    items = require_list(checklist.get("items"), "notice_checklist items")
    require(items, "notice_checklist items must not be empty")
    by_id: dict[str, dict] = {}
    for index, item in enumerate(items):
        item = require_object(item, f"notice_checklist items[{index}]")
        item_id = require_string(item.get("id"), f"notice_checklist items[{index}] id")
        require(item_id not in by_id, f"notice_checklist contains duplicate id: {item_id}")
        by_id[item_id] = item
    for expected_id in BLOCKED_BLOCKING_OPEN:
        require(expected_id in by_id, f"rights gate is missing blocking item: {expected_id}")
        entry = by_id[expected_id]
        expected_detail = BLOCKED_BLOCKER_DETAILS[expected_id]
        require(entry.get("blocking") is True, f"rights gate item is not blocking: {expected_id}")
        require(entry.get("status") == "OPEN", f"rights gate blocking item is not OPEN: {expected_id}")
        require(entry.get("action") == expected_detail["action"], f"rights gate item action changed: {expected_id}")
        require(entry.get("owner") == expected_detail["owner"], f"rights gate item owner changed: {expected_id}")
        require(entry.get("evidence") == expected_detail["evidence"], f"rights gate item evidence changed: {expected_id}")
    open_blocking = sorted(item_id for item_id, entry in by_id.items() if entry.get("blocking") is True and entry.get("status") == "OPEN")
    require(set(open_blocking) == BLOCKED_BLOCKING_OPEN_SET, "rights gate blocking-open set changed")
    require(set(blocking_open) == set(open_blocking), "inventory blocking_open does not match the open blocking items in PROVENANCE.json")
    provenance_fixtures = require_list(provenance.get("fixtures"), "provenance fixtures")
    require(provenance_fixtures, "provenance fixtures must not be empty")
    provenance_paths: list[str] = []
    for index, entry in enumerate(provenance_fixtures):
        entry = require_object(entry, f"provenance fixtures[{index}]")
        provenance_paths.append(validate_relative_path(entry.get("path"), f"provenance fixtures[{index}] path"))
        require("release_archive_member" in entry, f"provenance fixtures[{index}] is missing release_archive_member")
        require(entry.get("release_archive_member") is False, f"provenance fixtures[{index}] must not be a release archive member")
    require(set(provenance_paths) == set(AUTHORIZED_FIXTURE_PATHS), "fixture set in PROVENANCE.json changed")
    require(set(fixture_strings) == set(provenance_paths), "inventory fixture_paths do not match the fixture set in tests/fixtures/PROVENANCE.json")
    require(set(fixture_strings) == set(AUTHORIZED_FIXTURE_PATHS), "inventory fixture_paths changed")
    return {
        "state": "blocked",
        "publication_decision": provenance_decision,
        "notice_applicability": provenance_notice,
        "notice_checklist_status": require_string(checklist.get("status"), "notice_checklist status"),
        "blocking_open": list(BLOCKED_BLOCKING_OPEN),
        "source_status": "BLOCKED",
        "binary_status": "BLOCKED",
        "publication_authorized": False,
        "authorization": dict(BLOCKED_REVIEW_PUSH_AUTH),
        "review_ci_branch_push_authorization": dict(BLOCKED_REVIEW_PUSH_AUTH),
        "release_controls": None,
        "targets": [BLOCKED_TARGET],
        "archive_members": sorted(member_pairs),
        "generated_members": list(BLOCKED_GENERATED_MEMBERS),
        "all_archive_members": ["BUILD-INFO.json", "INSTALL.md", "LICENSE-MIT", "THIRD_PARTY_LICENSES.md", "astatine"],
        "forbidden_globs": sorted(forbidden_strings),
        "fixture_paths": sorted(fixture_strings),
    }


def _verify_regeneration_scripts(root: Path, provenance: dict) -> None:
    """R7: scripted fixture entries must resolve to the expected script and hash.

    The packager and distribution gate must fail closed if a recorded
    regeneration script is missing, swapped, or changed after its SHA-256 was
    recorded. Blocked-v1 behavior is handled by the separate blocked validator.
    """
    fixtures = require_list(provenance.get("fixtures"), "provenance fixtures")
    seen: dict[str, str] = {}
    for index, entry in enumerate(fixtures):
        entry = require_object(entry, f"provenance fixtures[{index}]")
        fixture_id = require_string(entry.get("id"), f"provenance fixtures[{index}] id")
        if fixture_id not in EXPECTED_REGENERATION_SCRIPTS:
            continue
        regeneration = require_object(
            entry.get("regeneration"), f"provenance fixtures[{index}] regeneration"
        )
        require(
            regeneration.get("status") == "scripted",
            f"{fixture_id} regeneration status must be scripted",
        )
        script = require_string(
            regeneration.get("script"), f"provenance fixtures[{index}] regeneration script"
        )
        require(
            script == EXPECTED_REGENERATION_SCRIPTS[fixture_id],
            f"{fixture_id} regeneration script changed; expected {EXPECTED_REGENERATION_SCRIPTS[fixture_id]}",
        )
        digest = require_string(
            regeneration.get("script_sha256"),
            f"provenance fixtures[{index}] regeneration script_sha256",
        )
        require(
            re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            f"{fixture_id} regeneration script_sha256 must be lowercase hex",
        )
        data = read_confined_bytes(root, script, f"regeneration script {fixture_id}")
        require(
            hashlib.sha256(data).hexdigest() == digest,
            f"regeneration script SHA-256 changed for {fixture_id}: {script}",
        )
        seen[fixture_id] = script
    require(
        set(seen) == set(EXPECTED_REGENERATION_SCRIPTS)
        and set(seen.values()) == set(EXPECTED_REGENERATION_SCRIPTS.values()),
        "scripted regeneration coverage must include FIX-01 and FIX-02 with their expected scripts",
    )


def _validate_release_intent(
    root: Path, provenance: dict, inventory: dict
) -> dict:
    require(
        inventory.get("schema") == INTENT_INVENTORY_SCHEMA,
        f"unexpected distribution inventory schema: {inventory.get('schema')!r}",
    )
    scope = require_string(inventory.get("scope"), "distribution inventory scope")
    require(scope == INTENT_INVENTORY_SCOPE, "distribution inventory scope changed; the v0.1.0-testnet.6 candidate scope must be recorded exactly")
    require(
        provenance.get("schema") == INTENT_PROVENANCE_SCHEMA,
        f"unexpected fixture provenance schema: {provenance.get('schema')!r}",
    )
    release_identity = require_object(inventory.get("release"), "distribution inventory release")
    require(
        release_identity == RELEASE_IDENTITY,
        "distribution inventory release identity changed; the current candidate must be exactly v0.1.0-testnet.6",
    )
    require(
        provenance.get("release") == RELEASE_IDENTITY,
        "fixture provenance release identity must mirror the current v0.1.0-testnet.6 candidate",
    )
    historical = require_object(
        inventory.get("historical_release_intent"), "distribution inventory historical_release_intent"
    )
    require(
        historical == HISTORICAL_RELEASE_INTENT,
        "historical .1 release intent record changed; its stored .1 fields must remain exact and must not be rewritten as .2",
    )
    require(
        provenance.get("historical_release_intent") == HISTORICAL_RELEASE_INTENT,
        "fixture provenance historical .1 release intent must mirror the preserved historical record",
    )
    historical_notes = read_confined_bytes(
        root, HISTORICAL_RELEASE_NOTES_REL, "historical .1 release notes"
    )
    require(
        hashlib.sha256(historical_notes).hexdigest() == HISTORICAL_RELEASE_NOTES_SHA256,
        "historical .1 release notes changed; preserve the historical .1 intent file byte-for-byte",
    )
    release_notes = read_confined_bytes(root, RELEASE_NOTES_REL, "current .6 release notes")
    require(
        hashlib.sha256(release_notes).hexdigest() == RELEASE_NOTES_SHA256,
        "current .6 release notes changed; update the reviewed notes hash deliberately so the non-independence disclosure cannot be silently edited",
    )
    gate = require_object(inventory.get("rights_gate"), "rights_gate")
    require(gate.get("source") == PROVENANCE_REL, "rights_gate source changed")
    # Removed v2 publication keys must stay gone; v3 authorizes intent only.
    for _old_key in ("publication_decision", "publication_authorization"):
        require(
            _old_key not in gate,
            f"rights_gate must not contain removed key: {_old_key}; v3 authorizes release intent only, not publication",
        )
    gate_decision = require_string(gate.get("rights_decision"), "rights_gate rights_decision")
    gate_notice = require_string(gate.get("notice_applicability"), "rights_gate notice_applicability")
    require(gate_decision == INTENT_RIGHTS_DECISION, "rights_gate rights_decision is not the exact owner-authorized release-intent text; data-only edits cannot authorize release intent")
    require(gate_notice == INTENT_NOTICE_APPLICABILITY, "rights_gate notice_applicability is not the exact technical-review text")
    blocking_open = require_list(gate.get("blocking_open"), "rights_gate blocking_open")
    require(blocking_open == [], "rights_gate blocking_open must be [] for the release-intent state")
    require(gate.get("fail_closed") is True, "rights_gate fail_closed must be true")
    require(require_string(gate.get("rule"), "rights_gate rule") == INTENT_RULE, "rights_gate rule changed; the release-intent rule must be recorded exactly")
    # Release-intent authorization mirror.
    inventory_auth = require_object(gate.get("release_intent_authorization"), "rights_gate release_intent_authorization")
    require(require_string(inventory_auth.get("status"), "release_intent_authorization status") == INTENT_RELEASE_INTENT_STATUS, "release_intent_authorization status changed")
    require("publication" not in inventory_auth.get("status", "").lower(), "release_intent_authorization must not claim publication; v3 authorizes intent only")
    require(inventory_auth.get("authorized_by") == INTENT_AUTHORIZED_BY, "release_intent_authorization author changed; only the project owner authorizes release intent")
    require(inventory_auth.get("authorized_on") == INTENT_AUTHORIZED_ON, "release_intent_authorization date changed")
    require(require_string(inventory_auth.get("scope"), "release_intent_authorization scope") == INTENT_SCOPE, "release_intent_authorization scope changed")
    require(require_string(inventory_auth.get("approval_roles"), "release_intent_authorization approval_roles") == INTENT_APPROVAL_ROLES, "release_intent_authorization approval_roles changed; no separate release approver exists")
    evidence = require_list(inventory_auth.get("evidence"), "release_intent_authorization evidence")
    require(evidence, "release_intent_authorization evidence must not be empty")
    require(all(isinstance(item, str) and item for item in evidence), "release_intent_authorization evidence must be non-empty strings")
    technical = require_object(inventory_auth.get("technical_notice_review"), "release_intent_authorization technical_notice_review")
    require(require_string(technical.get("reviewed_by"), "technical_notice_review reviewed_by") == INTENT_TECHNICAL_REVIEWED_BY, "technical_notice_review reviewer changed")
    require(require_string(technical.get("reviewed_on"), "technical_notice_review reviewed_on") == INTENT_TECHNICAL_REVIEWED_ON, "technical_notice_review date changed")
    require_string(technical.get("finding"), "technical_notice_review finding")
    citations = require_list(technical.get("citations"), "technical_notice_review citations")
    require(citations, "technical_notice_review citations must not be empty")
    for index, citation in enumerate(citations):
        validate_relative_path(citation, f"technical_notice_review citations[{index}]")
        read_confined_bytes(root, citation, f"technical_notice_review citation {citation}")
    require(technical.get("legal_conclusion") is False, "technical review must not claim a legal conclusion")
    require(technical.get("separate_approval") is False, "technical review must not claim a separate approval")
    require(inventory_auth.get("final_release_controls_complete") is False, "final release controls must remain outstanding; v3 does not authorize final publication")
    not_authorized = require_list(inventory_auth.get("not_authorized"), "release_intent_authorization not_authorized")
    require(not_authorized, "release_intent_authorization not_authorized must not be empty")
    require(all(isinstance(item, str) and item for item in not_authorized), "release_intent_authorization not_authorized must be non-empty strings")
    require(inventory_auth.get("independent_verification") is False, "release intent must not be represented as independent verification")
    require(
        inventory_auth.get("owner_self_approval") == OWNER_SELF_APPROVAL_POLICY,
        "release_intent_authorization must record the explicit owner self-approval policy exactly",
    )
    require(
        inventory_auth.get("independent_reviewer") is False,
        "release_intent_authorization must not claim an independent reviewer",
    )
    require(
        inventory_auth.get("separation_of_duties")
        == OWNER_SELF_APPROVAL_POLICY["separation_of_duties"],
        "release_intent_authorization must not claim separation of duties",
    )
    # Rights-gate-level technical review mirror.
    gate_technical = require_object(gate.get("technical_notice_review"), "rights_gate technical_notice_review")
    require(gate_technical == technical, "rights_gate technical_notice_review does not mirror release_intent_authorization")
    # Superseded review/CI record retains prior fields.
    gate_push = require_object(gate.get("review_ci_branch_push_authorization"), "rights_gate review_ci_branch_push_authorization")
    require(gate_push.get("status") == INTENT_REVIEW_STATUS, "review/CI record must be marked SUPERSEDED \u2014 OWNER-AUTHORIZED RELEASE INTENT")
    require(gate_push.get("superseded_by") == INTENT_REVIEW_SUPERSEDED_BY, "review/CI superseded_by changed")
    require(gate_push.get("superseded_on") == INTENT_REVIEW_SUPERSEDED_ON, "review/CI superseded_on changed")
    for key, expected in BLOCKED_REVIEW_PUSH_AUTH.items():
        if key == "status":
            continue
        if key == "rights_gate_unchanged":
            expected = INTENT_REVIEW_PUSH_GATE
        require(gate_push.get(key) == expected, f"review/CI prior field changed: {key}; history must be retained exactly")

    source_dist = require_object(inventory.get("source_distribution"), "source_distribution")
    require(source_dist.get("status") == "RELEASE-INTENT-AUTHORIZED", "source distribution must be RELEASE-INTENT-AUTHORIZED in the release-intent state; data-only edits cannot authorize distribution")
    require("publication" not in str(source_dist.get("status")).lower(), "source distribution must not claim publication; v3 authorizes intent only")
    require(source_dist.get("final_release_controls_complete") is False, "source distribution final release controls must remain outstanding")
    require(require_string(source_dist.get("reason"), "source_distribution reason") == INTENT_SOURCE_REASON, "source_distribution reason changed")
    binary = require_object(inventory.get("binary_distribution"), "binary_distribution")
    require(binary.get("status") == "RELEASE-INTENT-AUTHORIZED", "binary distribution must be RELEASE-INTENT-AUTHORIZED in the release-intent state")
    require("publication" not in str(binary.get("status")).lower(), "binary distribution must not claim publication; v3 authorizes intent only")
    require(binary.get("final_release_controls_complete") is False, "binary distribution final release controls must remain outstanding")
    require_string(binary.get("reason"), "binary_distribution reason")
    require(require_string(binary.get("reason"), "binary_distribution reason") == INTENT_BINARY_REASON, "binary_distribution reason changed")
    targets = require_list(binary.get("targets"), "binary_distribution targets")
    require(list(targets) == list(AUTHORIZED_TARGETS), f"binary_distribution targets changed: {targets!r}")
    require("target" not in binary, "binary_distribution must use targets (plural) in the release-intent state")
    member_pairs, generated_pairs, forbidden_strings, fixture_strings = _check_archive_sets(
        binary, AUTHORIZED_ARCHIVE_MEMBERS, AUTHORIZED_GENERATED_MEMBERS, "release-intent allowlist"
    )
    require(
        generated_pairs == list(AUTHORIZED_GENERATED_MEMBERS),
        "binary_distribution generated_members changed; expected the ordered release-intent contract",
    )
    # Release controls: any weakening fails.
    controls = require_object(inventory.get("release_controls"), "release_controls")
    require(require_string(controls.get("status"), "release_controls status") == AUTHORIZED_RELEASE_CONTROLS["status"], "release_controls status changed")
    require(controls.get("workflow") == AUTHORIZED_RELEASE_CONTROLS["workflow"], "release_controls workflow changed")
    require(controls.get("environment") == AUTHORIZED_RELEASE_CONTROLS["environment"], "release_controls environment changed")
    require(controls.get("environment_required_reviewer") is True, "release_controls must require a reviewer")
    require(controls.get("environment_prevent_self_review") is False, "release_controls must record the explicit owner self-approval exception: prevent_self_review must be exactly false, not silently true")
    require(controls.get("environment_reviewer_owner_id") == EXPECTED_RELEASE_REVIEWER_ID, "release_controls must pin the immutable numeric owner reviewer id 86115037")
    require(controls.get("environment_reviewer_owner_login") == EXPECTED_RELEASE_REVIEWER_LOGIN, "release_controls must pin the owner reviewer login")
    require(controls.get("independent_environment_review") is False, "release_controls must not claim independent environment review")
    require(controls.get("owner_self_approval") is True, "release_controls must explicitly record owner self-approval")
    require(
        controls.get("owner_self_approval_policy") == OWNER_SELF_APPROVAL_POLICY,
        "release_controls owner_self_approval_policy changed; the explicit security tradeoff and residual risk must remain recorded",
    )
    require(controls.get("publication_mode") == AUTHORIZED_RELEASE_CONTROLS["publication_mode"], "release_controls publication_mode changed; the draft-only manual-publish mode cannot be weakened by data edits")
    require(controls.get("manual_publish_required") is True, "release_controls manual_publish_required must be true")
    require(controls.get("tag_policy") == AUTHORIZED_RELEASE_CONTROLS["tag_policy"], "release_controls tag_policy changed; it must be the exact current tag policy, not a series wildcard")
    require(controls.get("exact_tag_required") is True, "release_controls exact_tag_required must be true")
    require(controls.get("tag_ruleset_exact_scope") == EXPECTED_TAG_RULESET_SCOPE, "release_controls tag_ruleset_exact_scope must be exactly refs/tags/v* with no exclusions to preserve live breadth")
    require(controls.get("final_release_controls_complete") is False, "release_controls final release controls must remain outstanding")
    require(controls.get("immutable_release") is True, "release_controls immutable_release must be true as the recorded repository setting; verified immutable behavior additionally requires external admin verification")
    require(controls.get("immutable_tag_required") is True, "release_controls immutable_tag_required must be true")
    require(controls.get("tag_creation_ruleset_name") == EXPECTED_RELEASE_TAG_CREATION_RULESET_NAME, "release_controls tag_creation_ruleset_name changed")
    require(controls.get("tag_creation_rule_required") is True, "release_controls must retain the tag creation rule")
    require(controls.get("tag_creation_bypass_actors_allowed") == [dict(actor) for actor in EXPECTED_RELEASE_TAG_CREATION_BYPASS_ACTORS], "release_controls must pin exactly the owner-user (User 86115037, always) creation bypass; repository-admin bypass is rejected")
    require(controls.get("tag_immutability_ruleset_name") == EXPECTED_RELEASE_TAG_IMMUTABILITY_RULESET_NAME, "release_controls tag_immutability_ruleset_name changed")
    require(controls.get("tag_immutability_scope") == list(EXPECTED_TAG_IMMUTABILITY_SCOPE), "release_controls tag_immutability_scope must be exactly [\"refs/tags/v*\"] with no exclusions to preserve live breadth")
    require(controls.get("tag_immutability_bypass_actors_allowed") == 0, "release_controls must allow zero immutability-ruleset bypass actors")
    require(controls.get("immutable_setting_admin_verification_required") is True, "release_controls immutable_setting_admin_verification_required must be true")
    require(list(controls.get("attestations", [])) == list(AUTHORIZED_RELEASE_CONTROLS["attestations"]), "release_controls attestations changed")
    require(controls.get("exact_tag_main_ci") is True, "release_controls exact_tag_main_ci must be true")
    require(list(controls.get("external_blockers", [])) == list(AUTHORIZED_RELEASE_CONTROLS["external_blockers"]), "release_controls external_blockers changed; external blockers cannot be weakened by data edits")
    require(require_string(controls.get("offline_verification"), "release_controls offline_verification") == AUTHORIZED_RELEASE_CONTROLS["offline_verification"], "release_controls offline_verification changed")

    # Provenance cross-check.
    rights = require_object(provenance.get("rights_review"), "rights_review")
    for _old_key in ("publication_decision", "publication_authorization"):
        require(
            _old_key not in rights,
            f"rights_review must not contain removed key: {_old_key}; v3 authorizes release intent only, not publication",
        )
    provenance_decision = require_string(rights.get("rights_decision"), "rights_review rights_decision")
    provenance_notice = require_string(rights.get("notice_applicability"), "rights_review notice_applicability")
    require(provenance_decision == INTENT_RIGHTS_DECISION, "rights gate rights decision is not the exact owner-authorized text")
    require(provenance_notice == INTENT_NOTICE_APPLICABILITY, "NOTICE applicability must be exactly the technical-review text")
    require(gate_decision == provenance_decision, "inventory rights_decision does not match tests/fixtures/PROVENANCE.json")
    require(gate_notice == provenance_notice, "inventory notice_applicability does not match tests/fixtures/PROVENANCE.json")
    require(rights.get("rights_holder_authority") == ATTESTED_RIGHTS, "rights status must remain honest (owner-attested, not independently verified)")
    attestation = require_object(rights.get("owner_attestation"), "rights_review owner_attestation")
    require(attestation.get("status") == ATTESTED_RIGHTS, "owner attestation status must remain honest")
    require(attestation.get("independent_verification") is False, "owner attestation must not be represented as independent verification")
    provenance_auth = require_object(rights.get("release_intent_authorization"), "rights_review release_intent_authorization")
    require(provenance_auth == inventory_auth, "inventory release_intent_authorization does not mirror tests/fixtures/PROVENANCE.json")
    require(
        rights.get("owner_self_approval") == OWNER_SELF_APPROVAL_POLICY,
        "fixture provenance must record the explicit owner self-approval policy exactly",
    )
    require(
        rights.get("historical_release_intent") == HISTORICAL_RELEASE_INTENT,
        "fixture provenance historical .1 release intent changed",
    )
    provenance_push = require_object(rights.get("review_ci_branch_push_authorization"), "rights_review review_ci_branch_push_authorization")
    require(provenance_push == gate_push, "inventory review/CI record does not mirror tests/fixtures/PROVENANCE.json")
    checklist = require_object(rights.get("notice_checklist"), "rights_review notice_checklist")
    require(require_string(checklist.get("status"), "notice_checklist status") == INTENT_CHECKLIST_STATUS, "notice checklist status is not the exact technical-review-recorded text")
    items = require_list(checklist.get("items"), "notice_checklist items")
    require(items, "notice_checklist items must not be empty")
    by_id: dict[str, dict] = {}
    for index, item in enumerate(items):
        item = require_object(item, f"notice_checklist items[{index}]")
        item_id = require_string(item.get("id"), f"notice_checklist items[{index}] id")
        require(item_id not in by_id, f"notice_checklist contains duplicate id: {item_id}")
        by_id[item_id] = item
    for expected_id in ("RIGHTS-01", "RIGHTS-02", "RIGHTS-03", "RIGHTS-04", "RIGHTS-05"):
        require(expected_id in by_id, f"rights gate is missing checklist item: {expected_id}")
        entry = by_id[expected_id]
        require(entry.get("blocking") is True, f"rights gate item is not blocking: {expected_id}")
        require(entry.get("status") == "DONE", f"rights gate item is not DONE: {expected_id}")
        require_string(entry.get("action"), f"rights gate item action {expected_id}")
        require_string(entry.get("owner"), f"rights gate item owner {expected_id}")
        require(entry.get("evidence"), f"rights gate item evidence is missing: {expected_id}")
    # Actions stay the blocked canonical text; owners are the v3-recorded
    # owners. Rewording the gate cannot imply approval.
    require(by_id["RIGHTS-01"].get("action") == INTENT_RIGHTS_01_ACTION, "rights gate item action changed: RIGHTS-01")
    for expected_id in BLOCKED_BLOCKING_OPEN:
        require(by_id[expected_id].get("action") == BLOCKED_BLOCKER_DETAILS[expected_id]["action"], f"rights gate item action changed: {expected_id}")
    for expected_id, expected_owner in INTENT_CHECKLIST_OWNERS.items():
        require(by_id[expected_id].get("owner") == expected_owner, f"rights gate item owner changed: {expected_id}")
    open_blocking = sorted(item_id for item_id, entry in by_id.items() if entry.get("blocking") is True and entry.get("status") == "OPEN")
    require(open_blocking == [], "rights gate blocking-open set must be empty for the release-intent state")

    # Fixtures: paths unchanged, none may be an archive member.
    provenance_fixtures = require_list(provenance.get("fixtures"), "provenance fixtures")
    require(provenance_fixtures, "provenance fixtures must not be empty")
    provenance_paths: list[str] = []
    for index, entry in enumerate(provenance_fixtures):
        entry = require_object(entry, f"provenance fixtures[{index}]")
        provenance_paths.append(validate_relative_path(entry.get("path"), f"provenance fixtures[{index}] path"))
        require("release_archive_member" in entry, f"provenance fixtures[{index}] is missing release_archive_member")
        require(entry.get("release_archive_member") is False, f"provenance fixtures[{index}] must not be a release archive member")
        # Substantive license evidence for bytecode fixtures.
        license_info = entry.get("license")
        if entry.get("path") in (
            "tests/fixtures/AstatineMiner.json",
            "tests/fixtures/AstatineGenesisCoordinator.json",
            "tests/fixtures/MockAST.json",
        ):
            license_info = require_object(license_info, f"provenance fixtures[{index}] license")
            require_string(license_info.get("declared_spdx"), f"provenance fixtures[{index}] license declared_spdx")
            require_string(license_info.get("declaration_evidence"), f"provenance fixtures[{index}] license declaration_evidence")
            rights_status = require_string(license_info.get("rights_status"), f"provenance fixtures[{index}] license rights_status")
            require("unresolved" not in rights_status.lower(), f"provenance fixtures[{index}] license rights_status remains unresolved; data-only edits cannot authorize release intent")
            license_text = require_string(license_info.get("license_text"), f"provenance fixtures[{index}] license license_text")
            validate_relative_path(license_text, f"provenance fixtures[{index}] license license_text")
            require(license_text in AUTHORIZED_LEGAL_ARTIFACT_PATHS, f"provenance fixtures[{index}] license_text is not an authorized legal artifact: {license_text}")
            require_string(license_info.get("copyright"), f"provenance fixtures[{index}] license copyright")
    require(set(provenance_paths) == set(AUTHORIZED_FIXTURE_PATHS), "fixture set in PROVENANCE.json changed; refusing to authorize against a moved gate")
    _verify_regeneration_scripts(root, provenance)
    require(set(fixture_strings) == set(provenance_paths), "inventory fixture_paths do not match the fixture set in tests/fixtures/PROVENANCE.json")

    # Legal artifacts: all four must exist, match hashes, and carry markers.
    legal_artifacts = require_list(provenance.get("legal_artifacts"), "legal_artifacts")
    require(legal_artifacts, "legal artifact inventory is empty")
    artifact_by_path: dict[str, dict] = {}
    for index, artifact in enumerate(legal_artifacts):
        label = f"legal_artifacts[{index}]"
        artifact = require_object(artifact, label)
        path = validate_relative_path(artifact.get("path"), f"{label} path")
        require(path not in artifact_by_path, f"duplicate legal artifact path: {path}")
        artifact_by_path[path] = artifact
    require(set(artifact_by_path) == set(AUTHORIZED_LEGAL_ARTIFACT_PATHS), f"legal artifact set changed; expected {sorted(AUTHORIZED_LEGAL_ARTIFACT_PATHS)!r}")
    for path in sorted(AUTHORIZED_LEGAL_ARTIFACT_PATHS):
        artifact = artifact_by_path[path]
        data = read_confined_bytes(root, path, f"legal artifact {path}")
        require(len(data) == artifact.get("bytes"), f"{path} byte length changed")
        require(hashlib.sha256(data).hexdigest() == artifact.get("sha256"), f"{path} SHA-256 changed")
        text = data.decode("utf-8", errors="strict") if _is_utf8(data) else ""
        if path == "tests/fixtures/LICENSE-APACHE-2.0.txt":
            require("Apache License" in text and "Version 2.0" in text, f"{path} is not the Apache-2.0 license text")
        elif path == "tests/fixtures/LICENSE-MIT.txt":
            require("MIT License" in text and "Permission is hereby granted" in text, f"{path} is not the MIT license text")
        elif path == "tests/fixtures/NOTICE":
            require("Astatine fixture NOTICE" in text, f"{path} is not the fixture NOTICE")
            require("Copyright (c) 2026" in text, f"{path} is missing the fixture copyright")
            require("no separate" in text.lower() and "upstream" in text.lower(), f"{path} is missing the no-upstream-NOTICE decision")
        elif path == "tests/fixtures/OPENZEPPELIN_LICENSE.txt":
            require("The MIT License (MIT)" in text, f"{path} is not the MIT license text")
    # License text references in fixture records must resolve to real files.
    for index, entry in enumerate(provenance_fixtures):
        entry = require_object(entry, f"provenance fixtures[{index}]")
        license_info = entry.get("license")
        if isinstance(license_info, dict) and "license_text" in license_info:
            license_text = validate_relative_path(license_info.get("license_text"), f"provenance fixtures[{index}] license license_text")
            read_confined_bytes(root, license_text, f"fixture license_text {license_text}")

    return {
        "state": "release-intent-authorized",
        "rights_decision": provenance_decision,
        "notice_applicability": provenance_notice,
        "notice_checklist_status": require_string(checklist.get("status"), "notice_checklist status"),
        "blocking_open": [],
        "source_status": "RELEASE-INTENT-AUTHORIZED",
        "binary_status": "RELEASE-INTENT-AUTHORIZED",
        "release_intent_authorized": True,
        "publication_authorized": False,
        "final_release_controls_complete": False,
        "release_intent_authorization": dict(inventory_auth),
        "owner_self_approval": dict(OWNER_SELF_APPROVAL_POLICY),
        "historical_release_intent": dict(HISTORICAL_RELEASE_INTENT),
        "release": dict(RELEASE_IDENTITY),
        "technical_notice_review": dict(technical),
        "review_ci_branch_push_authorization": dict(gate_push),
        "release_controls": dict(controls),
        "targets": list(AUTHORIZED_TARGETS),
        "archive_members": sorted(member_pairs),
        "generated_members": list(AUTHORIZED_GENERATED_MEMBERS),
        "all_archive_members": ["BUILD-INFO.json", "INSTALL.md", "LICENSE-MIT", "THIRD_PARTY_LICENSES.md", "astatine", "astatine.exe"],
        "forbidden_globs": sorted(forbidden_strings),
        "fixture_paths": sorted(fixture_strings),
    }


def _is_utf8(data: bytes) -> bool:
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def load_gate(root: Path, *, require_release_version: bool = False) -> dict:
    """Load and validate the release gate for ``root``.

    Reads exactly ``tests/fixtures/PROVENANCE.json`` and
    ``support/release/distribution-inventory.json`` (canonical paths only),
    validates the blocked or release-intent-authorized shape, cross-checks
    inventory against provenance, requires substantive license evidence and
    controls, and returns at least ``state`` (``blocked`` or
    ``release-intent-authorized``), ``rights_decision`` (or blocked
    ``publication_decision``), ``notice_applicability``, ``source_status``,
    ``binary_status``, ``release_intent_authorized``,
    ``publication_authorized``, ``final_release_controls_complete``,
    ``release_intent_authorization`` (or blocked ``authorization``),
    ``technical_notice_review``, ``release_controls``, ``targets``,
    ``archive_members``, ``generated_members``, ``forbidden_globs``,
    ``fixture_paths``, ``repository``, and ``package_version``. Release
    callers pass ``require_release_version=True`` to bind the Cargo package
    version to the current ``v0.1.0-testnet.6`` candidate; the nonpublishing
    dry-run leaves it false for synthetic historical fixtures.

    Raises :class:`GateError` fail-closed on any mismatch. Stdlib-only and
    offline; no network, build, wallet, or publication side effects.
    """
    try:
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise GateError("source root is not readable") from error
    require(resolved.is_dir(), "source root is not a directory")
    # Canonical gate paths only; no overrides exist so a caller cannot
    # substitute an old blocked copy after the real gate changes.
    provenance_bytes = read_confined_bytes(resolved, PROVENANCE_REL, "fixture provenance")
    inventory_bytes = read_confined_bytes(resolved, INVENTORY_REL, "distribution inventory")
    provenance = parse_json_object(provenance_bytes, PROVENANCE_REL)
    inventory = parse_json_object(inventory_bytes, INVENTORY_REL)
    schema = inventory.get("schema")
    if schema == BLOCKED_INVENTORY_SCHEMA:
        gate = _validate_blocked(resolved, provenance, inventory)
    elif schema == INTENT_INVENTORY_SCHEMA:
        gate = _validate_release_intent(resolved, provenance, inventory)
    else:
        raise GateError(f"unexpected distribution inventory schema: {schema!r}")
    # Repository and package version are part of the gate record so builders
    # can bind artifacts to the exact source identity without re-parsing.
    repository = read_confined_bytes(resolved, REPOSITORY_REL, "release repository").decode("utf-8").strip()
    require(repository == EXPECTED_REPOSITORY, f"release repository changed: {repository!r}")
    cargo_text = read_confined_bytes(resolved, CARGO_TOML_REL, "cargo manifest").decode("utf-8")
    package_name, package_version = parse_cargo_package(cargo_text)
    if require_release_version:
        require(
            package_version == EXPECTED_RELEASE_VERSION,
            f"Cargo package version must be exactly {EXPECTED_RELEASE_VERSION!r}, got {package_version!r}",
        )
    # The shared gate also serves the nonpublishing dry-run against synthetic
    # historical package versions; release callers must opt into the exact .3
    # version check. The final release builder opts in, and the workflow also
    # checks Cargo.toml directly.
    gate["repository"] = repository
    gate["package_version"] = package_version
    gate["package_name"] = package_name
    gate["inventory_path"] = INVENTORY_REL
    gate["provenance_path"] = PROVENANCE_REL
    return gate
