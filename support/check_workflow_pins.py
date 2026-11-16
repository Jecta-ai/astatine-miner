#!/usr/bin/env python3
"""Fail if a workflow uses a mutable external action reference."""

from __future__ import annotations

import pathlib
import re
import sys
import tempfile


USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
IMMUTABLE_SHA = re.compile(r"[0-9a-f]{40}\Z")

DRY_RUN_WORKFLOW_FILENAME = "linux-release-dry-run.yml"
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
    self_test()
    root = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(".github/workflows")
    errors: list[str] = []
    scanned = 0
    workflows = sorted({*root.glob("*.yml"), *root.glob("*.yaml")})
    for workflow in workflows:
        contents = workflow.read_text(encoding="utf-8")
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
