#!/usr/bin/env python3
"""Fail if a workflow uses a mutable external action reference.

Release workflow pin: support/check_workflow_pins.py pins the exact
.github/workflows/release.yml bytes via RELEASE_WORKFLOW_SHA256. Recompute
after reviewed edits with:
  python3 -B support/check_workflow_pins.py --print-release-sha256
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import sys
import tempfile


USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
IMMUTABLE_SHA = re.compile(r"[0-9a-f]{40}\Z")

DRY_RUN_WORKFLOW_FILENAME = "linux-release-dry-run.yml"
RELEASE_WORKFLOW_FILENAME = "release.yml"
# Pinned SHA-256 of .github/workflows/release.yml. Update only after review.
# Recompute with: python3 -B support/check_workflow_pins.py --print-release-sha256
RELEASE_WORKFLOW_SHA256 = "57a0d1f9949883b77a8d64c04a26a8bc18c0499dde024e83b46576c9cebe2caa"
PINNED_RELEASE_ACTIONS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/upload-artifact": "cf430e030ddbb5b0abf93d22962f4752f3646cd9",
    "actions/download-artifact": "9000827ccba6bdab643e8b6fd33ac0654aef8333",
    "actions/attest-build-provenance": "4d101475d8b20a2381f78447822ac1eab6504dd8",
}
RELEASE_TAG_PATTERN = r"^v[0-9]+\.[0-9]+\.[0-9]+-testnet\.[0-9]+$"
WRITE_KEY_ALTERNATION = (
    "actions|attestations|checks|contents|deployments|discussions|id-token|issues|"
    "packages|pages|pull-requests|repository-projects|security-events|statuses"
)
_PLAIN_PERMISSION_VALUE = re.compile(r"(read|write|none)\s*(?:#.*)?\Z")
_PLAIN_PERMISSION_KEY = re.compile(r"[A-Za-z][A-Za-z0-9-]*\Z")


class _AmbiguousWorkflow(Exception):
    pass


def dry_run_workflow_path() -> pathlib.Path:
    """Exact repository path of the dry-run workflow (used only by self-test)."""
    return (
        pathlib.Path(__file__).resolve().parents[1]
        / ".github"
        / "workflows"
        / DRY_RUN_WORKFLOW_FILENAME
    )


def release_workflow_path() -> pathlib.Path:
    """Exact repository path of the release workflow."""
    return (
        pathlib.Path(__file__).resolve().parents[1]
        / ".github"
        / "workflows"
        / RELEASE_WORKFLOW_FILENAME
    )


def compute_release_sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def _release_run_blocks(contents: str) -> list[str]:
    """Extract shell bodies from `run:` steps (inline and block scalars)."""
    blocks: list[str] = []
    lines = contents.splitlines()
    index = 0
    total = len(lines)
    while index < total:
        line = lines[index]
        stripped = line.strip()
        if stripped.startswith("#"):
            index += 1
            continue
        match = re.match(r"^(?P<indent>\s*)run\s*:\s*(?P<rest>.*)$", line)
        if not match:
            index += 1
            continue
        indent = len(match.group("indent"))
        rest = match.group("rest").strip()
        if rest in ("|", ">", "|-", "|+", ">-", ">+"):
            index += 1
            body: list[str] = []
            while index < total:
                nxt = lines[index]
                if nxt.strip() == "":
                    body.append("")
                    index += 1
                    continue
                nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                if nxt_indent <= indent:
                    break
                body.append(nxt)
                index += 1
            blocks.append("\n".join(body))
            continue
        if rest.startswith("|") or rest.startswith(">"):
            index += 1
            body = []
            while index < total:
                nxt = lines[index]
                if nxt.strip() == "":
                    body.append("")
                    index += 1
                    continue
                nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                if nxt_indent <= indent:
                    break
                body.append(nxt)
                index += 1
            blocks.append("\n".join(body))
            continue
        if rest != "":
            blocks.append(rest)
        index += 1
    return blocks


def _release_job_permissions(contents: str) -> dict[str, dict[str, str]]:
    """Map job name to its plain permissions mapping.

    Raises _AmbiguousWorkflow on non-plain syntax so permission scoping
    cannot be bypassed with flow maps, quoted keys, or explicit keys.
    """
    lines = contents.splitlines()
    in_jobs = False
    current_job: str | None = None
    perms_indent: int | None = None
    result: dict[str, dict[str, str]] = {}
    index = 0
    total = len(lines)
    while index < total:
        raw = lines[index]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        leading = raw[: len(raw) - len(raw.lstrip())]
        if "\t" in leading:
            raise _AmbiguousWorkflow(f"line {index + 1}: tab indentation")
        indent = len(leading)
        if indent == 0:
            top = re.match(r"([^:]+?)\s*:\s*(.*)$", stripped)
            if top and top.group(1).strip() == "jobs":
                rest = top.group(2).strip()
                if rest not in ("", "#"):
                    # jobs must be a block mapping, not inline
                    raise _AmbiguousWorkflow(f"line {index + 1}: inline jobs value")
                in_jobs = True
                current_job = None
                perms_indent = None
            elif top:
                in_jobs = False
                current_job = None
                perms_indent = None
            index += 1
            continue
        if not in_jobs:
            index += 1
            continue
        if perms_indent is not None:
            if indent <= perms_indent:
                perms_indent = None
            else:
                if stripped.startswith("?") or re.match(r"<<\s*:", stripped):
                    raise _AmbiguousWorkflow(f"line {index + 1}: non-plain permissions entry")
                match = re.match(r"([^:]+?)\s*:\s*(.*)$", stripped)
                if not match:
                    raise _AmbiguousWorkflow(f"line {index + 1}: unparseable permissions entry")
                key, value = match.group(1), match.group(2)
                if not _PLAIN_PERMISSION_KEY.fullmatch(key):
                    raise _AmbiguousWorkflow(f"line {index + 1}: non-plain permission key {key!r}")
                if re.search(r"[{}\[\]*&!|>;]", value):
                    raise _AmbiguousWorkflow(f"line {index + 1}: non-plain permission value {value!r}")
                plain = _PLAIN_PERMISSION_VALUE.fullmatch(value)
                if not plain:
                    raise _AmbiguousWorkflow(f"line {index + 1}: ambiguous permission value {value!r}")
                if current_job is None:
                    raise _AmbiguousWorkflow(f"line {index + 1}: permissions outside job")
                result.setdefault(current_job, {})[key] = plain.group(1)
                index += 1
                continue
        if indent == 2:
            job_match = re.match(r"([A-Za-z0-9_-]+)\s*:\s*(.*)$", stripped)
            if job_match:
                rest = job_match.group(2).strip()
                if rest != "" and not rest.startswith("#"):
                    raise _AmbiguousWorkflow(f"line {index + 1}: inline job value")
                current_job = job_match.group(1)
                result.setdefault(current_job, {})
                index += 1
                continue
        if indent == 4 and current_job is not None:
            perm_match = re.match(r"^permissions\s*:\s*(.*)$", stripped)
            if perm_match:
                rest = perm_match.group(1).strip()
                if rest != "" and not rest.startswith("#"):
                    raise _AmbiguousWorkflow(f"line {index + 1}: inline permissions value {rest!r}")
                perms_indent = indent
                index += 1
                continue
        # Detect ambiguous permission constructs inside jobs
        if re.match(r"^\?\s*['\"]?permissions['\"]?\s*(?::|$)", stripped):
            raise _AmbiguousWorkflow(f"line {index + 1}: explicit permissions key")
        if re.match(r"^['\"]permissions['\"]\s*:", stripped):
            raise _AmbiguousWorkflow(f"line {index + 1}: quoted permissions key")
        if re.match(r"^permissions\s+:", stripped):
            raise _AmbiguousWorkflow(f"line {index + 1}: spaced permissions key")
        index += 1
    return result


def _release_job_environments(contents: str) -> list[tuple[str, str, int]]:
    """Return (job, environment value, lineno) for each `environment:` key."""
    lines = contents.splitlines()
    in_jobs = False
    current_job: str | None = None
    found: list[tuple[str, str, int]] = []
    for lineno, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        leading = raw[: len(raw) - len(raw.lstrip())]
        indent = len(leading)
        if indent == 0:
            top = re.match(r"([^:]+?)\s*:\s*(.*)$", stripped)
            if top and top.group(1).strip() == "jobs":
                in_jobs = True
                current_job = None
            elif top:
                in_jobs = False
                current_job = None
            continue
        if not in_jobs:
            continue
        if indent == 2:
            job_match = re.match(r"([A-Za-z0-9_-]+)\s*:\s*(?:#.*)?$", stripped)
            if job_match:
                current_job = job_match.group(1)
            continue
        env_match = re.match(r"^environment\s*:\s*(.*)$", stripped)
        if env_match:
            rest = env_match.group(1).strip()
            if rest == "" or rest.startswith("#"):
                raise _AmbiguousWorkflow(f"line {lineno}: block environment is ambiguous")
            value = re.sub(r"\s*(?:#.*)?$", "", rest).strip().strip("'\"")
            found.append((current_job or "", value, lineno))
    return found


ALWAYS_PRIVILEGED_WORKFLOW_PATTERNS = (
    ("GitHub secrets context", re.compile(r"\bsecrets\b", re.IGNORECASE)),
    ("write-all permission", re.compile(r"(?mi)^\s*permissions\s*:\s*write-all\b")),
    ("contents write permission", re.compile(r"\bcontents\s*:\s*write\b", re.IGNORECASE)),
    (
        "flow-style permission",
        re.compile(r":\s*\{[^}\n]*", re.IGNORECASE),
    ),
    (
        "flow-style write permission",
        re.compile(r":\s*\{[^}\n]*:\s*write\b", re.IGNORECASE),
    ),
    (
        "explicit-key permission",
        re.compile(
            r"(?mi)^\s*\?\s*(?:" + WRITE_KEY_ALTERNATION + r")\s*\n\s*:\s*write\b",
            re.IGNORECASE,
        ),
    ),
    (
        "quoted permission key",
        re.compile(
            r"(?mi)^\s*['\"](?:" + WRITE_KEY_ALTERNATION + r")['\"]\s*:",
            re.IGNORECASE,
        ),
    ),
    (
        "explicit permissions key",
        re.compile(r"(?mi)^\s*\?\s*['\"]?permissions['\"]?\s*(?::|$)", re.IGNORECASE),
    ),
    (
        "spaced permission key",
        re.compile(r"(?mi)^\s*permissions\s+:", re.IGNORECASE),
    ),
    (
        "quoted uses key",
        re.compile(r"(?mi)^\s*(?:-\s*)?['\"]uses['\"]\s*:", re.IGNORECASE),
    ),
    (
        "spaced uses key",
        re.compile(r"(?mi)^\s*(?:-\s*)?uses\s+:", re.IGNORECASE),
    ),
    (
        "explicit uses key",
        re.compile(r"(?mi)^\s*\?\s*['\"]?uses['\"]?\s*(?::|$)", re.IGNORECASE),
    ),
    (
        "quoted permissions block key",
        re.compile(r"(?mi)^\s*['\"]permissions['\"]\s*:", re.IGNORECASE),
    ),
    (
        "merge key",
        re.compile(r"(?mi)^\s*<<\s*:", re.IGNORECASE),
    ),
    (
        "YAML anchor definition",
        re.compile(r":\s*&[A-Za-z_]", re.IGNORECASE),
    ),
    (
        "semicolon permission line",
        re.compile(
            r"(?mi)^\s*(?:" + WRITE_KEY_ALTERNATION + r")\s*:[^#\n]*;",
            re.IGNORECASE,
        ),
    ),
    (
        "signing environment",
        re.compile(r"\benvironment\s*:\s*['\"]?testnet-release-signing\b", re.IGNORECASE),
    ),
    (
        "publishing environment",
        re.compile(r"\benvironment\s*:\s*['\"]?testnet-release-publish\b", re.IGNORECASE),
    ),
    (
        "block-style signing/publishing environment",
        re.compile(
            r"(?mi)^\s*environment\s*:\s*\n\s*name\s*:\s*['\"]?testnet-release-(?:signing|publish)\b",
            re.IGNORECASE,
        ),
    ),
    ("signing secret name", re.compile(r"TESTNET_RELEASE_SIGNING_KEY|ASTATINE_RELEASE_SIGNING_KEY")),
    ("cargo publish", re.compile(r"\bcargo\s+publish\b", re.IGNORECASE)),
    ("npm publish", re.compile(r"\bnpm\s+publish\b", re.IGNORECASE)),
    ("docker push", re.compile(r"\bdocker\s+push\b", re.IGNORECASE)),
    ("git push", re.compile(r"\bgit\s+push\b", re.IGNORECASE)),
    ("gh release operation", re.compile(r"\bgh\s+release\b", re.IGNORECASE)),
    ("gh api releases operation", re.compile(r"\bgh\s+api\b[^\n]*releases\b", re.IGNORECASE)),
    ("twine upload", re.compile(r"\btwine\s+upload\b", re.IGNORECASE)),
    (
        "upload/release action",
        re.compile(
            r"(?mi)^\s*(?:-\s*)?uses:\s*[^\s#]*(?:upload-release|action-gh-release|"
            r"release-action|automatic-releases|upload-artifact)\b",
            re.IGNORECASE,
        ),
    ),
)


def permission_block_entries(contents: str) -> list[tuple[str, str, int]]:
    """Yield (key, value, lineno) for plain block entries under `permissions:` mappings.

    Raises _AmbiguousWorkflow on anything that is not an unambiguous plain
    block mapping (flow maps, quoted keys, explicit keys, block scalars,
    merge keys, anchors, aliases, tabs, semicolons, multi-token values).
    Block-scalar script bodies (e.g. multi-line `run:` scripts) are skipped
    structurally; they are still scanned by the raw tripwire patterns, which
    are never hidden by this parser.
    """
    entries: list[tuple[str, str, int]] = []
    lines = contents.splitlines()
    index = 0
    total = len(lines)
    perms_indent: int | None = None
    while index < total:
        raw = lines[index]
        lineno = index + 1
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        leading = raw[: len(raw) - len(raw.lstrip())]
        indent = len(leading)
        if "\t" in leading:
            raise _AmbiguousWorkflow(f"line {lineno}: tab indentation")
        if perms_indent is not None:
            if indent <= perms_indent:
                perms_indent = None
            else:
                if stripped.startswith("?") or re.match(r"<<\s*:", stripped):
                    raise _AmbiguousWorkflow(f"line {lineno}: non-plain permissions entry")
                match = re.match(r"([^:]+?)\s*:\s*(.*)$", stripped)
                if not match:
                    raise _AmbiguousWorkflow(f"line {lineno}: unparseable permissions entry")
                key, value = match.group(1), match.group(2)
                if not _PLAIN_PERMISSION_KEY.fullmatch(key):
                    raise _AmbiguousWorkflow(f"line {lineno}: non-plain permission key {key!r}")
                if re.search(r"[{}\[\]*&!|>;]", value):
                    raise _AmbiguousWorkflow(f"line {lineno}: non-plain permission value {value!r}")
                plain = _PLAIN_PERMISSION_VALUE.fullmatch(value)
                if not plain:
                    raise _AmbiguousWorkflow(f"line {lineno}: ambiguous permission value {value!r}")
                entries.append((key, plain.group(1), lineno))
                index += 1
                continue
        block_scalar = re.match(r"^(.+?)\s*:\s*[|>][-+]?\s*(?:#.*)?$", stripped)
        if block_scalar:
            key = block_scalar.group(1).strip()
            if key == "permissions":
                raise _AmbiguousWorkflow(f"line {lineno}: block-scalar permissions are ambiguous")
            index += 1
            while index < total and (
                not lines[index].strip()
                or (len(lines[index]) - len(lines[index].lstrip(" "))) > indent
            ):
                index += 1
            continue
        perm_block = re.match(r"^permissions\s*:\s*(.*)$", stripped)
        if perm_block:
            rest = perm_block.group(1).strip()
            if rest == "" or rest.startswith("#"):
                perms_indent = indent
            else:
                raise _AmbiguousWorkflow(f"line {lineno}: inline permissions value {rest!r}")
            index += 1
            continue
        index += 1
    return entries


def reference_for_line(line: str) -> str | None:
    match = USES.match(line)
    return match.group(1) if match else None


def is_pinned(reference: str) -> bool:
    if reference.startswith("./"):
        return True
    if "@" not in reference:
        return False
    return IMMUTABLE_SHA.fullmatch(reference.rsplit("@", 1)[1]) is not None


def validate_signing_isolation(contents: str, workflow: pathlib.Path) -> None:
    """Source-controlled tripwire; GitHub policy and offline custody remain authoritative.

    No workflow, including the blocked dry-run workflow, may request write
    permissions. The dry-run performs no attestation dispatch per the blocked
    distribution inventory, so no id-token or attestations grant exists.
    """
    contents = contents.lstrip("\ufeff")
    for description, pattern in ALWAYS_PRIVILEGED_WORKFLOW_PATTERNS:
        if pattern.search(contents):
            raise AssertionError(f"{workflow}: workflow contains forbidden release authority ({description})")
    try:
        entries = permission_block_entries(contents)
    except _AmbiguousWorkflow as error:
        raise AssertionError(f"{workflow}: workflow contains ambiguous permission syntax ({error})")
    for key, value, lineno in entries:
        if value != "write":
            continue
        raise AssertionError(
            f"{workflow}:{lineno}: workflow contains forbidden release authority "
            f"(write permission: {key})"
        )


def validate_release_workflow(contents: str, workflow: pathlib.Path) -> None:
    """Tightly reviewed release profile for release.yml only.

    Strict non-release workflows keep the no-write/no-secrets isolation above.
    release.yml is allowed only with: workflow_dispatch-only with a required
    string tag input, job-level least privilege (contents:write plus
    attestations:read only on publish, id-token/attestations:write only on
    package, environment only on publish), pinned actions, no secrets,
    no tag creation, no PR triggers, no git push, no registry publication,
    no mutable refs, and no persist-credentials:true. The exact bytes are
    additionally pinned via RELEASE_WORKFLOW_SHA256; edits must deliberately
    update the pin.
    """
    raw = contents.lstrip("\ufeff")
    # Structural ambiguity must fail closed even for release.
    for description, pattern in ALWAYS_PRIVILEGED_WORKFLOW_PATTERNS:
        if description in (
            "contents write permission",
            "gh release operation",
            "upload/release action",
        ):
            continue
        if pattern.search(raw):
            raise AssertionError(
                f"{workflow}: release workflow contains forbidden pattern ({description})"
            )
    try:
        permission_block_entries(raw)
    except _AmbiguousWorkflow as error:
        raise AssertionError(f"{workflow}: release workflow ambiguous syntax ({error})")
    try:
        job_perms = _release_job_permissions(raw)
    except _AmbiguousWorkflow as error:
        raise AssertionError(f"{workflow}: release workflow ambiguous job permissions ({error})")

    # Trigger profile: workflow_dispatch only, exact tag input.
    if re.search(r"(?mi)^\s*push\s*:", raw):
        raise AssertionError(f"{workflow}: release workflow must not define a push trigger")
    if re.search(r"(?mi)^\s*pull_request\s*:", raw):
        raise AssertionError(f"{workflow}: release workflow must not define a pull_request trigger")
    if re.search(r"(?mi)^\s*pull_request_target\s*:", raw):
        raise AssertionError(f"{workflow}: release workflow must not use pull_request_target")
    if "workflow_dispatch" not in raw:
        raise AssertionError(f"{workflow}: release workflow must be workflow_dispatch only")
    tag_block = re.search(
        r"(?ms)^\s*tag\s*:\s*\n(?:^\s*.*\n)*?",
        raw,
    )
    if not tag_block or "required: true" not in raw or "type: string" not in raw:
        raise AssertionError(f"{workflow}: release workflow must declare a required string tag input")
    if re.search(r"(?mi)^\s*default\s*:", raw):
        raise AssertionError(f"{workflow}: release tag input must not define a default substitute")

    # Top-level least privilege and identity.
    if not re.search(r"(?m)^permissions:\s*\n\s*contents:\s*read\s*(?:#.*)?$", raw):
        raise AssertionError(f"{workflow}: release workflow top-level permissions must be contents: read")
    if "concurrency:" not in raw or "cancel-in-progress: false" not in raw:
        raise AssertionError(f"{workflow}: release workflow concurrency must disable cancel-in-progress")
    if "release-${{ inputs.tag }}" not in raw:
        raise AssertionError(f"{workflow}: release concurrency must be keyed by the release tag")
    if 'RUSTUP_TOOLCHAIN: "1.94.1"' not in raw:
        raise AssertionError(f"{workflow}: release workflow must pin RUSTUP_TOOLCHAIN 1.94.1")
    if "RELEASE_TAG: ${{ inputs.tag }}" not in raw:
        raise AssertionError(f"{workflow}: release workflow must expose RELEASE_TAG from inputs.tag")

    # Job set and job-level least privilege.
    # M1: packaging/attestation and draft creation occur only in protected
    # release-draft; builds are unprivileged except binary build attestations.
    expected_jobs = {"preflight", "build-macos", "build-linux", "release-package", "release-draft"}
    if set(job_perms) != expected_jobs:
        raise AssertionError(
            f"{workflow}: release jobs must be exactly {sorted(expected_jobs)}, got {sorted(job_perms)}"
        )
    expected_perms: dict[str, dict[str, str]] = {
        "preflight": {"contents": "read", "actions": "read"},
        "build-macos": {"contents": "read", "id-token": "write", "attestations": "write"},
        "build-linux": {"contents": "read", "id-token": "write", "attestations": "write"},
        "release-package": {
            "contents": "read",
            "id-token": "write",
            "attestations": "write",
            "actions": "read",
        },
        "release-draft": {"contents": "write", "actions": "read", "attestations": "read"},
    }
    for job, expected in expected_perms.items():
        actual = job_perms.get(job, {})
        if actual != expected:
            raise AssertionError(
                f"{workflow}: job {job} permissions must be exactly {expected}, got {actual}"
            )
    # Explicit scoped assertions for clear errors (B2 split).
    # release-package: protected build (no contents:write); release-draft: protected draft-only.
    for job, perms in job_perms.items():
        if perms.get("attestations") == "read" and job != "release-draft":
            raise AssertionError(
                f"{workflow}: attestations: read is allowed only on release-draft (found in {job})"
            )
        if perms.get("actions") == "read" and job not in ("preflight", "release-package", "release-draft"):
            raise AssertionError(
                f"{workflow}: actions: read is allowed only on preflight and protected jobs (found in {job})"
            )
        for key, value in perms.items():
            if value != "write":
                continue
            if key == "contents" and job != "release-draft":
                raise AssertionError(f"{workflow}: contents: write is allowed only on release-draft (found in {job})")
            if key in ("id-token", "attestations") and job not in (
                "build-macos",
                "build-linux",
                "release-package",
            ):
                raise AssertionError(
                    f"{workflow}: {key}: write is allowed only on builds and release-package (found in {job})"
                )
            if key not in ("contents", "id-token", "attestations", "actions"):
                raise AssertionError(f"{workflow}: unexpected write permission {key} in {job}")
        if perms.get("checks") == "read":
            raise AssertionError(
                f"{workflow}: checks: read is not used by the release profile (found in {job})"
            )

    # Both protected jobs are environment-gated (B2); no pre-approval package job.
    try:
        envs = _release_job_environments(raw)
    except _AmbiguousWorkflow as error:
        raise AssertionError(f"{workflow}: release workflow ambiguous environment ({error})")
    if len(envs) != 2:
        raise AssertionError(f"{workflow}: release workflow must define exactly two protected environments, got {envs}")
    env_jobs = sorted([job for job, _, _ in envs])
    if env_jobs != ["release-draft", "release-package"]:
        raise AssertionError(
            f"{workflow}: environment must be `release` only on release-package and release-draft, got {envs}"
        )
    for _, value, lineno in envs:
        if value != "release":
            raise AssertionError(
                f"{workflow}:{lineno}: environment must be `release`, got {value!r}"
            )

    # Runners and needs.
    for runner_need in (
        ("preflight", "ubuntu-24.04"),
        ("build-macos", "macos-15"),
        ("build-linux", "ubuntu-24.04"),
        ("release-package", "ubuntu-24.04"),
        ("release-draft", "ubuntu-24.04"),
    ):
        job, runner = runner_need
        if runner not in raw:
            raise AssertionError(f"{workflow}: job {job} must run on {runner}")
    if "needs:" not in raw:
        raise AssertionError(f"{workflow}: release jobs must declare needs dependencies")

    # Pinned actions with exact allowlist (L3): only the four pinned actions, no other uses even if pinned.
    for number, line in enumerate(raw.splitlines(), 1):
        reference = reference_for_line(line)
        if reference is None:
            continue
        if not is_pinned(reference):
            raise AssertionError(
                f"{workflow}:{number}: release action is not pinned to a full commit SHA: {reference}"
            )
        if reference.startswith("./"):
            raise AssertionError(
                f"{workflow}:{number}: local actions are not allowed in the release workflow: {reference}"
            )
        if "@" in reference:
            repo, sha = reference.rsplit("@", 1)
            if repo not in PINNED_RELEASE_ACTIONS:
                raise AssertionError(
                    f"{workflow}:{number}: unexpected external action {repo} in release workflow; exact allowlist only"
                )
            if sha != PINNED_RELEASE_ACTIONS[repo]:
                raise AssertionError(
                    f"{workflow}:{number}: {repo} must be pinned to {PINNED_RELEASE_ACTIONS[repo]}, got {sha}"
                )
    for repo, sha in PINNED_RELEASE_ACTIONS.items():
        if f"{repo}@{sha}" not in raw:
            raise AssertionError(f"{workflow}: release workflow must pin {repo}@{sha}")
    # Forbid other release/publish actions even when pinned.
    if re.search(r"upload-release-action|action-gh-release|release-action|automatic-releases", raw, re.IGNORECASE):
        raise AssertionError(f"{workflow}: release workflow uses a forbidden release action")

    # No tag creation, no pushes, no registry publication.
    if re.search(r"\bgit\s+tag\b", raw, re.IGNORECASE):
        raise AssertionError(f"{workflow}: release workflow must not create tags")
    if re.search(r"\bgh\s+api\b[^\n]*?(?:git/refs|refs/tags)", raw, re.IGNORECASE):
        # Tag re-verification uses read-only git ls-remote, never gh api tag refs.
        raise AssertionError(f"{workflow}: release workflow must not manage tags via gh api")
    if "persist-credentials: true" in raw:
        raise AssertionError(f"{workflow}: release workflow must not set persist-credentials: true")
    # Top-level permissions must be exactly contents: read (no extra top-level write).
    top_block = re.search(r"(?m)^permissions:\s*\n((?:[ \t]+[^\n]*\n)*)", raw)
    if not top_block:
        raise AssertionError(f"{workflow}: release workflow top-level permissions missing")
    top_lines = [ln.strip() for ln in top_block.group(1).splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if top_lines != ["contents: read"]:
        raise AssertionError(
            f"{workflow}: release workflow top-level permissions must be exactly contents: read, got {top_lines}"
        )
    # Every checkout must use the exact tag ref with fetch-depth 0 and no credentials.
    checkout_refs = re.findall(r"(?m)^\s*ref\s*:\s*(.+?)\s*(?:#.*)?$", raw)
    if not checkout_refs:
        raise AssertionError(f"{workflow}: release workflow checkouts must declare ref")
    for ref_value in checkout_refs:
        if ref_value.strip() != "refs/tags/${{ inputs.tag }}":
            raise AssertionError(
                f"{workflow}: every checkout ref must be refs/tags/${{{{ inputs.tag }}}}, got {ref_value!r}"
            )
    checkout_count = raw.count("actions/checkout@")
    persist_false = raw.count("persist-credentials: false")
    if checkout_count == 0 or persist_false < checkout_count:
        raise AssertionError(
            f"{workflow}: every checkout must set persist-credentials: false "
            f"(checkouts={checkout_count}, false={persist_false})"
        )
    fetch_count = raw.count("fetch-depth: 0")
    if fetch_count < checkout_count:
        raise AssertionError(
            f"{workflow}: every checkout must set fetch-depth: 0 "
            f"(checkouts={checkout_count}, fetch-depth={fetch_count})"
        )
    if re.search(r"(?mi)^\s*(?:-\s*)?uses\s*:\s*\{", raw):
        raise AssertionError(f"{workflow}: release workflow must not use flow-style uses:")
    if "refs/tags/${{ inputs.tag }}" not in raw:
        raise AssertionError(f"{workflow}: release checkouts must use refs/tags/${{{{ inputs.tag }}}}")
    if "GH_TOKEN: ${{ github.token }}" not in raw:
        raise AssertionError(f"{workflow}: release workflow must use GH_TOKEN: ${{{{ github.token }}}}")

    # gh release allowlist (draft-only): create with --draft, view, attestation verify.
    # Never edit/publish from the workflow; manual owner publication is outside.
    for match in re.finditer(r"\bgh\s+release\s+([A-Za-z-]+)", raw):
        sub = match.group(1)
        if sub not in ("create", "view"):
            raise AssertionError(
                f"{workflow}: forbidden gh release subcommand {sub!r}; "
                "allowed: create, view (draft-only; no edit/verify/publish)"
            )
    if "gh release edit" in raw:
        raise AssertionError(f"{workflow}: release workflow must not execute gh release edit (draft-only)")
    if "--draft=false" in raw:
        raise AssertionError(f"{workflow}: release workflow must not clear draft (no --draft=false)")
    if "--prerelease" in raw:
        raise AssertionError(f"{workflow}: release workflow must not mark prerelease from the workflow (draft-only)")
    if re.search(r"\bgh\s+release\s+verify\b", raw):
        raise AssertionError(f"{workflow}: release workflow must not auto-verify/publish releases")
    if "gh release verify-asset" in raw:
        raise AssertionError(f"{workflow}: release workflow must not auto-verify release assets")
    for required in (
        "gh release create",
        "gh release view",
        "--json assets",
        "--verify-tag",
        "--draft",
    ):
        if required not in raw:
            raise AssertionError(f"{workflow}: release workflow must contain {required!r}")
    if not re.search(r"gh\s+release\s+create\b[^\n]*--draft\b", raw):
        raise AssertionError(f"{workflow}: gh release create must contain --draft (draft-only)")
    if "--draft --verify-tag" not in raw and "--verify-tag" not in raw:
        raise AssertionError(f"{workflow}: gh release create must contain --verify-tag")
    if "cp support/release/RELEASE_NOTES-v0.1.0-testnet.1.md" not in raw:
        raise AssertionError(f"{workflow}: release package must copy the reviewed testnet notes into the bundle")
    if "--notes-file bundle/release-notes.md" not in raw:
        raise AssertionError(f"{workflow}: release draft must use bundle/release-notes.md for draft notes")
    if re.search(r"\bgh\s+release\s+create\b[^\n]*\bgit\b", raw, re.IGNORECASE):
        raise AssertionError(f"{workflow}: release creation must not shell out to git tag creation")

    # Attestation constraints must all be present and exact.
    for required in (
        "gh attestation verify",
        "--repo",
        "--signer-workflow",
        "--source-digest",
        "--source-ref",
        ".github/workflows/release.yml",
        'refs/tags/$tag"',
        '"$GITHUB_REPOSITORY"',
        '"$GITHUB_SHA"',
    ):
        if required not in raw:
            raise AssertionError(f"{workflow}: release attestation verification must contain {required!r}")
    for required in ("subject-path", "SHA256SUMS", "release-provenance.json"):
        if required not in raw:
            raise AssertionError(f"{workflow}: release bundle verification must contain {required!r}")
    if "sha256sum -c SHA256SUMS" not in raw:
        raise AssertionError(f"{workflow}: release workflow must verify SHA256SUMS")
    if "actions/attest-build-provenance@" not in raw:
        raise AssertionError(f"{workflow}: release workflow must attest archives with attest-build-provenance")

    # Tag input must never be interpolated directly into shell; use env and quote.
    for block in _release_run_blocks(raw):
        if "inputs.tag" in block:
            raise AssertionError(
                f"{workflow}: release tag input must not be interpolated in run scripts; use $RELEASE_TAG"
            )
        if "${{" in block:
            raise AssertionError(
                f"{workflow}: run scripts must not contain template interpolation; pass values via env"
            )
    if '"$RELEASE_TAG"' not in raw and '"$tag"' not in raw:
        raise AssertionError(f"{workflow}: release scripts must use the quoted tag variable")
    if RELEASE_TAG_PATTERN.strip("^$") not in raw and "^v[0-9]+" not in raw:
        raise AssertionError(f"{workflow}: release workflow must enforce the tag regex")
    if "$'\\n'" not in raw or "[^ -~]" not in raw:
        raise AssertionError(f"{workflow}: release workflow must reject newline/control characters")
    if "git describe --tags --exact-match" not in raw:
        raise AssertionError(f"{workflow}: release workflow must verify git describe --tags --exact-match")
    if "git rev-parse HEAD" not in raw or "$GITHUB_SHA" not in raw:
        raise AssertionError(f"{workflow}: release workflow must verify HEAD equals GITHUB_SHA")
    if "git merge-base --is-ancestor HEAD origin/main" not in raw:
        raise AssertionError(f"{workflow}: release workflow must verify ancestry from origin/main")
    if "Rust CI" not in raw or "Linux native qualification" not in raw:
        raise AssertionError(f"{workflow}: release workflow must require both hosted check suites")
    if ".github/workflows/ci.yml" not in raw:
        raise AssertionError(f"{workflow}: release workflow must require the exact Rust CI workflow path")
    if ".github/workflows/linux-native-qualification.yml" not in raw:
        raise AssertionError(f"{workflow}: release workflow must require the exact qualification workflow path")
    if "head_branch" not in raw or '"main"' not in raw:
        raise AssertionError(f"{workflow}: release workflow must require head_branch == main for push runs")
    if "workflow_dispatch is not a substitute" not in raw:
        raise AssertionError(f"{workflow}: release workflow must not treat workflow_dispatch as a substitute for the main push run")
    if "actions/runs?head_sha=" not in raw and "actions/runs" not in raw:
        raise AssertionError(f"{workflow}: release workflow must query exact-commit workflow runs via gh api")
    if "pull_request" not in raw:
        raise AssertionError(f"{workflow}: release workflow must explicitly exclude pull-request events")
    if 'git ls-remote origin "refs/tags/$tag"' not in raw:
        raise AssertionError(f"{workflow}: release workflow must re-verify the remote tag with git ls-remote")
    if "remote tag moved" not in raw or "remote tag verified at expected commit" not in raw:
        raise AssertionError(f"{workflow}: release workflow must fail closed on a moved tag")
    if '"$RUNNER_TEMP/published-assets.json"' not in raw and "published-assets.json" not in raw:
        raise AssertionError(f"{workflow}: release workflow must capture gh release view JSON for digest verification")
    if "digest mismatch" not in raw or "size mismatch" not in raw:
        raise AssertionError(f"{workflow}: release workflow must fail closed on digest/size mismatch")
    if "all assets verified with matching digest and size" not in raw:
        raise AssertionError(f"{workflow}: release workflow must verify digests and sizes for every expected asset")
    for marker in ("codesign --verify", "otool -L", "file ", "ldd "):
        if marker not in raw:
            raise AssertionError(f"{workflow}: release workflow must contain binary inspection {marker!r}")
    if "--version" not in raw or "mine --help" not in raw:
        raise AssertionError(f"{workflow}: release workflow must smoke test version/help/mine help")
    if "protected" not in raw.lower() or "fail closed" not in raw.lower():
        raise AssertionError(f"{workflow}: release workflow must document the protected-gate fail-closed prerequisite")
    if "external prerequisite" not in raw.lower():
        raise AssertionError(f"{workflow}: release workflow must document the external prerequisite")
    if "non-self" not in raw.lower():
        raise AssertionError(f"{workflow}: release workflow must document the non-self reviewer gate")
    if "tag deployment" not in raw.lower():
        raise AssertionError(f"{workflow}: release workflow must document the tag deployment policy")
    # Protected environment fail-closed verification via bounded validator (L2).
    # Preflight + re-verify before mutation in release-draft; no inline env python,
    # no reviewer identities printed. Validator enforces M2 series/exact allowlist.
    validator_cli = 'python3 -B support/release/verify-protected-environment.py --environment-json "$env_out" --policies-json "$policies_out" --tag "$tag"'
    if validator_cli not in raw:
        raise AssertionError(
            f"{workflow}: release workflow must call the protected-environment validator with {validator_cli!r}"
        )
    if raw.count(validator_cli) < 2:
        raise AssertionError(
            f"{workflow}: release workflow must call the protected-environment validator in preflight and re-verify before mutation"
        )
    for required in (
        'environments/release"',
        "deployment-branch-policies",
    ):
        if required not in raw:
            raise AssertionError(f"{workflow}: release workflow must contain protected-environment marker {required!r}")
    # M2: validator in preflight/package enforces series/exact; draft inline enforces
    # series/exact with no broad v*. Broad *, **, empty, and other broader patterns rejected.
    if '"v*"' in raw and '"v0.1.0-testnet.*"' not in raw.replace('"v*"', ''):
        # Allow series pattern but forbid bare broad v* (exact string with comma or brace context)
        pass
    # Forbid bare broad v* allowlist entry (exact "v*" as a standalone policy name)
    if '"v*", ' in raw or '{"v*"' in raw or ', "v*"' in raw:
        raise AssertionError(f"{workflow}: release workflow must not accept broad v* tag policy (M2: series/exact only)")
    if 'allowed_names = {"v0.1.0-testnet.*", tag}' not in raw:
        raise AssertionError(f"{workflow}: release-draft inline check must require series/exact allowlist (M2)")
    # M2 OR policy: exactly one tag policy, no second tag or branch (policies are OR).
    for required in (
        "tag policies must be exactly one",
        "branch policies must be empty",
        "tag policy name not in series/exact allowlist",
        "tag policy entry must be an object",
        "tag policy type must be exactly tag",
        "tag policy name missing",
        "allowed_names",
        '"v0.1.0-testnet.*"',
    ):
        if required not in raw:
            raise AssertionError(f"{workflow}: release workflow must enforce single-tag OR policy {required!r} (M2)")
    # Canonical repository enforcement (fail closed on forks).
    for required in (
        '"Jecta-ai/astatine-miner"',
        "1454137135",
        "REPOSITORY_ID",
    ):
        if required not in raw:
            raise AssertionError(f"{workflow}: release workflow must enforce canonical repository marker {required!r}")
    # Stronger gate verifiers in preflight.
    for required in (
        "python3 -B support/verify-fixture-provenance.py",
        "python3 -B support/verify-distribution-inventory.py",
    ):
        if required not in raw:
            raise AssertionError(f"{workflow}: release workflow must run gate verifier {required!r}")
    # Provenance semantic verification before ending at draft.
    # Owner-authorized release intent (not final publication): release_intent true,
    # publication_authorized false, final controls false; prefer rights_decision.
    for required in (
        "release provenance semantics verified",
        "provenance field tag mismatch",
        "provenance field commit mismatch",
        "provenance field repository mismatch",
        "provenance field repository_id mismatch",
        "provenance field release_intent_authorized must be exactly true",
        "provenance field publication_authorized must be exactly false",
        "provenance field final_release_controls_complete must be exactly false",
        "provenance field rights_decision missing or empty",
        "must record owner-authorized release intent",
        "must not claim publication authorization or a release approver",
        '["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"]',
        "provenance archive sha256 mismatch",
        "Draft verified; manual owner publication remains required",
        "owner-authorized release intent",
        "final controls",
    ):
        if required not in raw:
            raise AssertionError(f"{workflow}: release workflow must contain provenance semantic marker {required!r}")
    if "rights_decision" not in raw:
        raise AssertionError(f"{workflow}: release workflow must read rights_decision instead of publication_decision")
    if raw.count("provenance field rights_decision missing or empty") < 2:
        raise AssertionError(
            f"{workflow}: release workflow must enforce the rights_decision fail-closed check in both "
            "the package and draft provenance validators"
        )
    if "provenance field publication_authorized must be exactly true" in raw:
        raise AssertionError(f"{workflow}: release workflow must not require final-publication publication_authorized true")
    # Safe failure logging: only safe fields, never the full run object.
    if "html_url" not in raw:
        raise AssertionError(f"{workflow}: release workflow must log only safe run fields including html_url")
    if 'is not successful: %r" % (name, run)' in raw or "is not successful: %r' % (name, run)" in raw:
        raise AssertionError(f"{workflow}: release workflow must not print the full run object on failure")
    # L4: tag-ref dispatch and GITHUB_REF binding.
    if 'test "$GITHUB_REF" = "refs/tags/$' not in raw:
        raise AssertionError(f"{workflow}: release workflow must assert GITHUB_REF == refs/tags/$tag (L4)")
    if "refs/tags/<tag> via workflow_dispatch" not in raw and "exact tag ref" not in raw.lower():
        raise AssertionError(f"{workflow}: release workflow must document tag-ref dispatch (L4)")
    # L5: safe latest-push-run selection (tolerates reruns, rejects PR/dispatch).
    for required in (
        "run_started_at",
        "created_at",
        "latest = max",
    ):
        if required not in raw:
            raise AssertionError(f"{workflow}: release workflow must select latest push run via {required!r} (L5)")
    if "len(matching) != 1" in raw:
        raise AssertionError(f"{workflow}: release workflow must not use exact-one run matching (L5: use latest safe selection)")
    # B1: per-job exact tag identity immediately after every checkout.
    # preflight + 2 builds + release-package each assert HEAD, tag^{}, describe.
    if raw.count("Assert exact tag identity") < 4:
        raise AssertionError(f"{workflow}: release workflow must assert exact tag identity after every checkout (B1)")
    for required in (
        'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        'test "$(git rev-parse "$RELEASE_TAG^{}")" = "$GITHUB_SHA"',
        'test "$(git describe --tags --exact-match)" = "$RELEASE_TAG"',
        "remote tag moved",
        "remote tag verified at expected commit",
    ):
        if required not in raw:
            raise AssertionError(f"{workflow}: release workflow must contain B1 tag-identity marker {required!r}")
    # Package uses checkout-bound ls-remote before archive attest; draft (no checkout)
    # must use authenticated gh api tag-ref lookup with peeling before draft.
    if raw.count('git ls-remote origin "refs/tags/$tag"') < 1:
        raise AssertionError(f"{workflow}: release-package must re-verify remote tag with git ls-remote before archive attest (B1)")
    for required in (
        'gh api "repos/$repo/git/ref/tags/$tag"',
        'gh api "repos/$repo/git/tags/$obj_sha"',
        "unsupported tag object type",
        "remote tag ref missing",
    ):
        if required not in raw:
            raise AssertionError(f"{workflow}: release-draft must verify remote tag via no-checkout gh api with peeling (B1)")
    _draft_section = raw.split("release-draft:", 1)[-1] if "release-draft:" in raw else ""
    if 'git ls-remote origin' in _draft_section:
        raise AssertionError(f"{workflow}: release-draft must not use git ls-remote (no checkout/no origin); use gh api tag ref (B1)")
    _draft_binary_verify = (
        'gh attestation verify "$binary" --repo "$GITHUB_REPOSITORY" '
        '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml" '
        '--source-digest "$GITHUB_SHA" --source-ref "refs/tags/$tag"'
    )
    if _draft_binary_verify not in _draft_section:
        raise AssertionError(
            f"{workflow}: release-draft must verify each extracted packaged binary with exact repo, "
            "signer workflow, source digest, and tag flags"
        )
    # L7: compilation binding via binary attestations.
    for required in (
        "Attest raw macOS binary",
        "Attest raw Linux binary",
        "subject-path: target/release/astatine",
        "Verify binary build attestations before packaging",
        'gh attestation verify "$binary"',
        "bound to compiled binaries",
        "archive attestation alone does not",
        "release-notes.md",
        "bundle/release-notes.md",
    ):
        if required not in raw:
            raise AssertionError(f"{workflow}: release workflow must contain compilation-binding marker {required!r} (L7)")
    # Draft-side binding: the packaged archive member must be the separately
    # attested compiled binary, not merely covered by an archive attestation.
    for required in (
        "Verify packaged binaries match attested compiled binaries",
        "Verify extracted binaries against build attestations",
        "archive member must be a regular file",
        "archive member path is unsafe",
        "archive member mode mismatch",
        "packaged binary sha256 does not match provenance",
        "macOS binary format mismatch",
        "Linux binary format mismatch",
        "0x0100000C",
        'int.from_bytes(binary[18:20], "little") != 62',
        "binary[4] != 2 or binary[5] != 1",
        "packaged binaries match archive and provenance allowlists",
        "packaged binaries verified against separately attested compiled binaries",
    ):
        if required not in raw:
            raise AssertionError(
                f"{workflow}: release-draft must bind packaged binaries to build attestations with marker {required!r}"
            )
    if "extractall(" in raw:
        raise AssertionError(
            f"{workflow}: release workflow must not use tar extractall; extract only validated regular-file members"
        )
    if raw.count('gh attestation verify "$binary"') < 2:
        raise AssertionError(
            f"{workflow}: release workflow must verify binary attestations in both release-package and release-draft"
        )
    # B2/M1: bundle artifact only between protected jobs; no unprotected package job.
    # release-package uploads, release-draft downloads; both are environment-gated.
    if "astatine-release-bundle" not in raw:
        raise AssertionError(f"{workflow}: release workflow must use the protected bundle artifact path (B2)")
    if re.search(r"(?m)^\s*package\s*:", raw):
        raise AssertionError(f"{workflow}: release workflow must not define an unprotected package job (B2/M1)")
    if raw.count("astatine-release-bundle") < 2:
        raise AssertionError(f"{workflow}: bundle artifact must be uploaded by release-package and downloaded by release-draft (B2)")
    # B2: per-job isolation — package builds (no contents:write, no draft mutation);
    # draft creates draft only (no checkout, no repo scripts/build).
    # Checkout count must be exactly preflight+2 builds+package (draft has none).
    _checkout_total = raw.count("actions/checkout@")
    if _checkout_total != 4:
        raise AssertionError(f"{workflow}: release workflow must have exactly 4 checkouts (preflight+builds+package, none in draft), got {_checkout_total} (B2)")
    # Validator script only in preflight + package (draft uses inline, no repo script).
    if raw.count('python3 -B support/release/verify-protected-environment.py --environment-json "$env_out" --policies-json "$policies_out" --tag "$tag"') != 2:
        raise AssertionError(f"{workflow}: protected-environment validator must run in preflight and package only (2x), inline in draft (B2/L2)")
    # Builder only in package.
    if raw.count("support/release/build-release.py") != 1:
        raise AssertionError(f"{workflow}: release builder must run exactly once in release-package (B2)")
    # Draft must create the draft exactly once; package must not.
    if raw.count("gh release create") != 1:
        raise AssertionError(f"{workflow}: gh release create must appear exactly once in release-draft (B2 draft-only)")
    if "Assert exact tag identity" not in raw or raw.count("Assert exact tag identity") < 4:
        raise AssertionError(f"{workflow}: release workflow must assert tag identity after every checkout (B1: preflight+builds+package)")
    # Draft inline env check markers (no validator script in draft).
    for _m in (
        "Re-verify protected environment before mutation",
        "tag policies must be exactly one",
        "branch policies must be empty",
    ):
        if _m not in raw:
            raise AssertionError(f"{workflow}: release-draft must contain inline env marker {_m!r} (B2)")

    # Exact-bytes pin: any edit must deliberately update the pin after review.
    digest = compute_release_sha256(contents.encode("utf-8"))
    if digest != RELEASE_WORKFLOW_SHA256:
        raise AssertionError(
            f"{workflow}: release workflow hash mismatch: got {digest}, "
            f"pinned {RELEASE_WORKFLOW_SHA256}; recompute with "
            "`python3 -B support/check_workflow_pins.py --print-release-sha256` after review"
        )


def self_test() -> None:
    fixtures = {
        "  - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567": True,
        "    uses: actions/checkout@0123456789abcdef0123456789abcdef01234567": True,
        "  - uses: ./support/local-action": True,
        "  - uses: actions/checkout@v7": False,
        "    uses: actions/checkout@main": False,
        "  - uses: actions/checkout": False,
        "  - uses: actions/checkout@0123456789ABCDEF0123456789ABCDEF01234567": False,
    }
    for line, expected in fixtures.items():
        reference = reference_for_line(line)
        actual = reference is not None and is_pinned(reference)
        if actual != expected:
            raise AssertionError(f"action pin fixture failed: {line!r}; expected {expected}, got {actual}")
    for privileged in (
        "env: SOME_KEY: ${{ secrets.SOME_KEY }}",
        "env: TESTNET_RELEASE_SIGNING_KEY: ${{ secrets.TESTNET_RELEASE_SIGNING_KEY }}",
        "permissions: contents: write",
        "permissions: contents : write",
        "permissions: write-all",
        "permissions:\n  id-token: write",
        "permissions:\n  packages: write",
        "permissions: {contents: read, packages: write}",
        "permissions:\n  ? packages\n  : write",
        "? permissions",
        "? permissions : write",
        "? \"permissions\"",
        "  ? 'permissions'",
        "permissions :",
        "permissions  : read",
        "  - uses : actions/checkout@v4",
        "  - \"uses\": actions/checkout@v4",
        "  - 'uses': actions/checkout@v4",
        "? uses",
        "? uses : actions/checkout@v4",
        "permissions:\n  \"contents\": write",
        "permissions:\n  'packages': write",
        "\"id-token\": write",
        "\"permissions\":\n  packages: write",
        "\ufeffpermissions:\n  packages: write",
        "\tpermissions:\n\t  packages: write",
        "permissions:\n  id-token: write; gh release create v1",
        "permissions:\n  id-token: |",
        "permissions:\n  <<: *base",
        "env: ${{ toJSON(secrets) }}",
        "if: contains(github.event.head_commit.message, secrets.KEY)",
        "environment: testnet-release-signing",
        "environment: testnet-release-publish",
        "environment:\n  name: testnet-release-signing",
        "environment:\n  name: testnet-release-publish",
        "run: gh release create v0.1.0-testnet.18",
        "run: GH_TOKEN=$TOKEN gh release upload v0.1.0-testnet.18 asset.zip",
        "run: gh release list",
        "run: echo 'gh release'",
        "run: gh api repos/o/r/releases --jq '.[].id'",
        "if: false\nrun: cargo publish --locked",
        "run: cargo publish --locked",
        "run: npm publish --provenance",
        "run: docker push example/image:tag",
        "run: git push origin main",
        "run: twine upload dist/*",
        "  - uses: svenstaro/upload-release-action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "  - uses: softprops/action-gh-release@da71618bb71b84d36a82a092de5a7c9d8d07743",
        "  - uses: actions/upload-artifact@ea165f8d65b6e768d8804778e0b7a12593b8bd12",
    ):
        try:
            validate_signing_isolation(privileged, pathlib.Path("synthetic-workflow.yml"))
        except AssertionError:
            continue
        raise AssertionError(f"workflow isolation fixture unexpectedly accepted: {privileged}")
    exact = dry_run_workflow_path()
    other = pathlib.Path("synthetic-workflow.yml")
    read_only = "permissions:\n  contents: read\n"
    validate_signing_isolation(read_only, exact)
    validate_signing_isolation(read_only, other)
    for forbidden_write in (
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\n",
        "permissions:\n  contents: read\n  id-token: write\n",
        "permissions:\n  contents: read\n  attestations: write\n",
        "permissions:\n  id-token: write\n",
        "permissions:\n  attestations: write\n",
    ):
        for target in (exact, other):
            try:
                validate_signing_isolation(forbidden_write, target)
            except AssertionError:
                continue
            raise AssertionError(
                f"write permission unexpectedly accepted for {target}: {forbidden_write!r}"
            )
    with tempfile.TemporaryDirectory(prefix="astatine-same-name-") as tmp:
        same_named = pathlib.Path(tmp) / DRY_RUN_WORKFLOW_FILENAME
        same_named.write_text(read_only, encoding="utf-8")
        validate_signing_isolation(read_only, same_named)
        try:
            validate_signing_isolation(
                "permissions:\n  contents: read\n  attestations: write\n",
                same_named,
            )
        except AssertionError:
            pass
        else:
            raise AssertionError("attestations write unexpectedly accepted for same-named path")
    try:
        validate_signing_isolation(read_only, pathlib.Path(DRY_RUN_WORKFLOW_FILENAME))
    except AssertionError as error:
        raise AssertionError(f"read-only dry-run filename check failed: {error}")
    shell_lookalike = (
        "permissions:\n  contents: read\n"
        "jobs:\n"
        "  demo:\n"
        "    steps:\n"
        "      - run: |\n"
        "          attestations: write\n"
        "          id-token: write\n"
    )
    validate_signing_isolation(shell_lookalike, exact)
    try:
        validate_signing_isolation(
            "permissions:\n  contents: read\n# packages: write\n", other
        )
    except AssertionError:
        raise AssertionError("comment-only permission lookalike must stay inert")
    for still_forbidden in (
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\n  packages: write\n",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\n  packages : write\n",
        "permissions: {contents: read, id-token: write, attestations: write, packages: write}",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\n  ? packages\n  : write",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\n? permissions",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\npermissions :",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\n  - uses : actions/checkout@v4",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\n  - \"uses\": actions/checkout@v4",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\n? uses",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\n  \"packages\": write",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\n  attestations: write; gh release create v1",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\n  id-token: |",
        "permissions:\n  contents: write\n  id-token: write\n  attestations: write\n",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\nenv: ${{ secrets.SOME_KEY }}\n",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\nrun: gh release create v0.1.0\n",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\nrun: cargo publish\n",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\nrun: docker push x/y\n",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\nrun: twine upload dist/*\n",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\nenvironment: testnet-release-signing\n",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\nenvironment: testnet-release-publish\n",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\nenvironment:\n  name: testnet-release-signing\n",
        "permissions:\n  contents: read\n  id-token: write\n  attestations: write\n  - uses: softprops/action-gh-release@da71618bb71b84d36a82a092de5a7c9d8d07743\n",
    ):
        try:
            validate_signing_isolation(still_forbidden, exact)
        except AssertionError:
            continue
        raise AssertionError(
            f"dry-run workflow fixture unexpectedly accepted: {still_forbidden!r}"
        )


def main() -> None:
    if "--print-release-sha256" in sys.argv:
        path = release_workflow_path()
        digest = compute_release_sha256(path.read_bytes())
        print(digest)
        return
    if "--help" in sys.argv or "-h" in sys.argv:
        print(
            "Usage: python3 -B support/check_workflow_pins.py [workflow-dir]\n"
            "       python3 -B support/check_workflow_pins.py --print-release-sha256\n"
            "Recompute the pinned release.yml SHA-256 after reviewed edits with --print-release-sha256."
        )
        return
    self_test()
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    root = pathlib.Path(args[0]) if args else pathlib.Path(".github/workflows")
    errors: list[str] = []
    scanned = 0
    workflows = sorted({*root.glob("*.yml"), *root.glob("*.yaml")})
    for workflow in workflows:
        contents = workflow.read_text(encoding="utf-8")
        if workflow.name == RELEASE_WORKFLOW_FILENAME:
            validate_release_workflow(contents, workflow)
        else:
            validate_signing_isolation(contents, workflow)
        for number, line in enumerate(contents.splitlines(), 1):
            reference = reference_for_line(line)
            if reference is None:
                continue
            scanned += 1
            if not is_pinned(reference):
                errors.append(f"{workflow}:{number}: external action is not pinned to a full commit SHA: {reference}")
    if errors:
        raise SystemExit("\n".join(errors))
    if scanned == 0:
        raise SystemExit("no workflow action references were found")
    print(f"Workflow action pin policy passed ({scanned} action references; both YAML step forms tested)")


if __name__ == "__main__":
    main()
