#!/usr/bin/env python3
"""Offline toolchain and dependency-advisory drift guard (E-02, E-07).

Static checks (always run, stdlib only, no network, no compilation):
  * rust-toolchain.toml channel, Cargo.toml rust-version, CI
    RUSTUP_TOOLCHAIN / installed version, and the Linux qualification and
    release dry-run workflow pins must all agree on exactly
    EXPECTED_TOOLCHAIN; a floating channel (e.g. "stable"), a `path =`
    override, or any contradictory duplicate occurrence fails.
  * Cargo.lock advisory state is self-clearing. The only affected lockfile
    entry with a documented exception is crypto-bigint 0.5.5. Zero
    crypto-bigint entries counts as cleared. Any other affected (<0.7.6)
    entry has no exception and fails. While 0.5.5 is present, at least one
    patched >=0.7.6 release must sit alongside it.
  * support/dependency-policy.md must record RUSTSEC-2026-0387, the patched
    >=0.7.6 line, the optional/inactive rationale, and the guarded
    exception with its revisit/removal obligation.
  * .github/workflows/ci.yml must keep a *live* (not commented out, not
    `if: false`-disabled) `run:` step invoking the inactive-graph guard.
    The `cargo audit --ignore RUSTSEC-2026-0387` exception is conditional:
    while an affected entry may be present in the lockfile the checker
    requires a live ignore step; once 0.5.5 is absent and every remaining
    locked crypto-bigint is patched (or none remain), the checker requires
    the exception to be removed and fails if it is still present. That
    future removal is a ci.yml edit which must only happen when the checker
    state flips -- never pre-emptively.
  * Cargo.toml must not gain a direct crypto-bigint dependency or an
    enabled k256 feature.

Runtime checks (--require-inactive only):
  * While crypto-bigint 0.5.5 is present: runs `cargo tree --locked
    --all-features --target all -i crypto-bigint@0.5.5` and fails if
    `crypto-bigint v0.5.5` appears.
  * Once 0.5.5 is absent: runs the positive active-graph check `cargo
    tree --locked --all-features --target all --prefix none` and fails if
    any active `crypto-bigint vX.Y.Z` line is <0.7.6, or if the command
    errors/times out. No active crypto-bigint lines means the dependency
    is removed and passes.
  These checks only verify which packages are outside/inside the active
  build graph; they do not state anything about advisory applicability.

Exit status is nonzero on any failure. Usage:
  python3 support/check_dependency_policy.py [--require-inactive] [--root PATH]
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

EXPECTED_TOOLCHAIN = "1.94.1"
ADVISORY_ID = "RUSTSEC-2026-0387"
PATCHED_LINE = ">=0.7.6"
PATCHED_MINIMUM = (0, 7, 6)
INACTIVE_PACKAGE = "0.5.5"
INACTIVE_PACKAGE_SPEC = "crypto-bigint@0.5.5"
INACTIVE_PACKAGE_VERSION = "crypto-bigint v0.5.5"
AUDIT_IGNORE_COMMAND = "cargo audit --ignore RUSTSEC-2026-0387"
GUARD_COMMAND = "python3 support/check_dependency_policy.py --require-inactive"
INACTIVE_TREE_CMD = (
    "cargo",
    "tree",
    "--locked",
    "--all-features",
    "--target",
    "all",
    "-i",
    INACTIVE_PACKAGE_SPEC,
)
ACTIVE_TREE_CMD = (
    "cargo",
    "tree",
    "--locked",
    "--all-features",
    "--target",
    "all",
    "--prefix",
    "none",
)
PINNED_WORKFLOWS = (
    "ci.yml",
    "linux-native-qualification.yml",
    "linux-release-dry-run.yml",
)

CHANNEL_RE = re.compile(r'(?m)^\s*channel\s*=\s*"([^"]+)"')
TOOLCHAIN_PATH_RE = re.compile(r"(?m)^\s*path\s*=")
RUST_VERSION_RE = re.compile(r'(?m)^\s*rust-version\s*=\s*"([^"]+)"')
TOOLCHAIN_ENV_RE = re.compile(r'RUSTUP_TOOLCHAIN:\s*"([^"]+)"')
TOOLCHAIN_INSTALL_RE = re.compile(r"rustup toolchain install\s+([0-9][0-9A-Za-z.\-]*)")
RUSTC_ASSERT_RE = re.compile(r'rustc --version.*=\s*"([^"]+)"')
CRYPTO_BIGINT_ENTRY_RE = re.compile(r'(?m)^name = "crypto-bigint"\nversion = "([^"]+)"')
ACTIVE_VERSION_RE = re.compile(r"^crypto-bigint v(\d+\.\d+\.\d+(?:[-+][^\s()]+)?)(?:\s+\(\*\))?\s*$")
STEP_SPLIT_RE = re.compile(r"(?m)^(?=\s*-\s+(?:name|uses|id)\s*:)")
STEP_IF_RE = re.compile(r"(?m)^\s*if:\s*(.+?)\s*$")
SINGLE_RUN_RE = re.compile(r"(?m)^\s*run:\s*([^\s|>].*?)\s*$")
TRAILING_COMMENT_RE = re.compile(r"\s+#.*$")


def default_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def read_text(path: pathlib.Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def check_toolchain_consistency(root: pathlib.Path) -> list[str]:
    errors: list[str] = []

    toolchain_text = read_text(root / "rust-toolchain.toml")
    if toolchain_text is None:
        errors.append("missing rust-toolchain.toml")
    else:
        if TOOLCHAIN_PATH_RE.search(toolchain_text):
            errors.append("rust-toolchain.toml must not use a `path =` override")
        channels = CHANNEL_RE.findall(toolchain_text)
        if not channels:
            errors.append("rust-toolchain.toml has no parseable channel")
        for channel in sorted(set(channels)):
            if channel != EXPECTED_TOOLCHAIN:
                errors.append(
                    "rust-toolchain.toml channel is %r, expected exactly %r"
                    % (channel, EXPECTED_TOOLCHAIN)
                )

    cargo_text = read_text(root / "Cargo.toml")
    if cargo_text is None:
        errors.append("missing Cargo.toml")
    else:
        rust_versions = RUST_VERSION_RE.findall(cargo_text)
        if not rust_versions:
            errors.append("Cargo.toml has no parseable rust-version")
        for version in sorted(set(rust_versions)):
            if version != EXPECTED_TOOLCHAIN:
                errors.append(
                    "Cargo.toml rust-version is %r, expected exactly %r"
                    % (version, EXPECTED_TOOLCHAIN)
                )

    for workflow in PINNED_WORKFLOWS:
        path = root / ".github" / "workflows" / workflow
        text = read_text(path)
        if text is None:
            errors.append("missing .github/workflows/%s" % workflow)
            continue
        env_versions = TOOLCHAIN_ENV_RE.findall(text)
        if not env_versions:
            errors.append("%s has no parseable RUSTUP_TOOLCHAIN" % workflow)
        for version in sorted(set(env_versions)):
            if version != EXPECTED_TOOLCHAIN:
                errors.append(
                    "%s RUSTUP_TOOLCHAIN is %r, expected exactly %r"
                    % (workflow, version, EXPECTED_TOOLCHAIN)
                )
        installs = TOOLCHAIN_INSTALL_RE.findall(text)
        if not installs:
            errors.append("%s has no rustup toolchain install line" % workflow)
        for version in sorted(set(installs)):
            if version != EXPECTED_TOOLCHAIN:
                errors.append(
                    "%s installs toolchain version %r, expected exactly %r"
                    % (workflow, version, EXPECTED_TOOLCHAIN)
                )
        asserted = RUSTC_ASSERT_RE.findall(text)
        if not asserted:
            errors.append(
                "%s has no exact `rustc --version` == %s assertion"
                % (workflow, EXPECTED_TOOLCHAIN)
            )
        for version in sorted(set(asserted)):
            if version != EXPECTED_TOOLCHAIN:
                errors.append(
                    "%s asserts rustc version %r, expected exactly %r"
                    % (workflow, version, EXPECTED_TOOLCHAIN)
                )
    return errors


def crypto_bigint_versions(lock_text: str) -> list[str]:
    return CRYPTO_BIGINT_ENTRY_RE.findall(lock_text)


def lockfile_has_inactive(lock_text: str) -> bool:
    return INACTIVE_PACKAGE in crypto_bigint_versions(lock_text)


def parse_dotted_version(text: str) -> tuple[int, ...] | None:
    # A semver pre-release (for example 0.7.6-alpha.1) sorts below 0.7.6 and
    # may still be affected; fail closed instead of stripping the suffix.
    if "-" in text:
        return None
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", text)
    if match is None:
        return None
    return tuple(int(group) for group in match.groups())


def lockfile_needs_exception(lock_text: str | None) -> bool:
    """True while an affected entry may be present (exception required)."""
    if lock_text is None:
        return True
    versions = crypto_bigint_versions(lock_text)
    if INACTIVE_PACKAGE in versions:
        return True
    for version in versions:
        parsed = parse_dotted_version(version)
        if parsed is None or parsed < PATCHED_MINIMUM:
            return True
    return False


def check_lockfile(root: pathlib.Path) -> list[str]:
    text = read_text(root / "Cargo.lock")
    if text is None:
        return ["missing Cargo.lock"]
    versions = crypto_bigint_versions(text)
    if not versions:
        return []
    unpatched = []
    unparseable = []
    for version in sorted(set(versions)):
        if version == INACTIVE_PACKAGE:
            continue
        parsed = parse_dotted_version(version)
        if parsed is None:
            unparseable.append(version)
        elif parsed < PATCHED_MINIMUM:
            unpatched.append(version)
    errors: list[str] = []
    if unparseable:
        errors.append(
            "Cargo.lock has unparseable crypto-bigint version(s) with no documented "
            "exception, cannot prove patched: %s" % ", ".join(unparseable)
        )
    if unpatched:
        errors.append(
            "Cargo.lock has affected crypto-bigint version(s) with no documented "
            "exception (only 0.5.5 carries the guarded exception): %s"
            % ", ".join(unpatched)
        )
    if lockfile_has_inactive(text):
        parsed = [parse_dotted_version(v) for v in versions]
        if not any(v is not None and v >= PATCHED_MINIMUM for v in parsed):
            errors.append(
                "Cargo.lock retains crypto-bigint 0.5.5 but has no patched "
                "crypto-bigint >=0.7.6 release alongside it"
            )
    return errors


def check_policy_doc(root: pathlib.Path) -> list[str]:
    text = read_text(root / "support" / "dependency-policy.md")
    if text is None:
        return ["missing support/dependency-policy.md"]
    lowered = text.lower()
    errors: list[str] = []
    if ADVISORY_ID not in text:
        errors.append("dependency-policy.md does not mention %s" % ADVISORY_ID)
    if PATCHED_LINE not in text:
        errors.append(
            "dependency-policy.md does not record the patched %s release line"
            % PATCHED_LINE
        )
    if "optional" not in lowered:
        errors.append("dependency-policy.md does not record the optional-dependency rationale")
    if "inactive" not in lowered and "active graph" not in lowered:
        errors.append(
            "dependency-policy.md does not record that the package is outside the active graph"
        )
    if "exception" not in lowered:
        errors.append("dependency-policy.md does not record the guarded exception")
    if "guarded exception" not in lowered:
        errors.append("dependency-policy.md does not state this is a guarded exception, not a clean fix")
    if "revisit" not in lowered:
        errors.append("dependency-policy.md does not carry the revisit-on-upstream-upgrade obligation")
    if "must be removed" not in lowered:
        errors.append(
            "dependency-policy.md does not describe the cleared-state transition: "
            "the audit exception must be removed once the advisory entry clears"
        )
    return errors


def live_run_commands(text: str) -> list[str]:
    """Single-line `run:` commands from enabled (non-`if: false`) steps.

    Comment-only lines and `run: |` block scalars never match, so a
    commented-out or disabled lookalike cannot satisfy the CI checks.
    """
    commands: list[str] = []
    for block in STEP_SPLIT_RE.split(text):
        if_match = STEP_IF_RE.search(block)
        if if_match and "false" in if_match.group(1).lower():
            continue
        for run_match in SINGLE_RUN_RE.finditer(block):
            commands.append(TRAILING_COMMENT_RE.sub("", run_match.group(1)).strip())
    return commands


def check_ci(root: pathlib.Path, lock_text: str | None) -> list[str]:
    text = read_text(root / ".github" / "workflows" / "ci.yml")
    if text is None:
        return ["missing .github/workflows/ci.yml"]
    commands = live_run_commands(text)
    errors: list[str] = []
    if GUARD_COMMAND not in commands:
        errors.append(
            "ci.yml has no live `run:` step invoking the inactive-graph guard "
            "(%s; comment-only or disabled steps do not count)" % GUARD_COMMAND
        )
    has_ignore = AUDIT_IGNORE_COMMAND in commands
    if lockfile_needs_exception(lock_text):
        if not has_ignore:
            errors.append(
                "ci.yml has no live `run:` step with `%s` "
                "(comment-only or disabled steps do not count)" % AUDIT_IGNORE_COMMAND
            )
    elif has_ignore:
        errors.append(
            "ci.yml still carries `%s` after the advisory entry cleared "
            "(0.5.5 absent, no affected lockfile entry remains): "
            "the exception must be removed" % AUDIT_IGNORE_COMMAND
        )
    return errors


def check_no_direct_dep(root: pathlib.Path) -> list[str]:
    text = read_text(root / "Cargo.toml")
    if text is None:
        return ["missing Cargo.toml"]
    errors: list[str] = []
    if re.search(r"(?m)^\s*crypto-bigint\s*=", text):
        errors.append("Cargo.toml gained a direct crypto-bigint dependency")
    if "k256" in text:
        errors.append("Cargo.toml references k256 (the optional k256 feature must stay disabled)")
    return errors


def run_static_checks(root: pathlib.Path) -> list[str]:
    lock_text = read_text(root / "Cargo.lock")
    errors: list[str] = []
    errors.extend(check_toolchain_consistency(root))
    errors.extend(check_lockfile(root))
    errors.extend(check_policy_doc(root))
    errors.extend(check_ci(root, lock_text))
    errors.extend(check_no_direct_dep(root))
    return errors


def run_cargo_tree(root: pathlib.Path, extra_args: tuple[str, ...]) -> tuple[int, str] | str:
    cmd = [
        "cargo",
        "tree",
        "--locked",
        "--all-features",
        "--target",
        "all",
        "--color",
        "never",
        *extra_args,
    ]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(root),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return "inactive-graph check could not run cargo tree (timeout)"
    except (OSError, subprocess.SubprocessError):
        # Withhold absolute checkout paths, command lines, and OS details;
        # still fail closed so the caller investigates.
        return "inactive-graph check could not run cargo tree (execution failed)"
    return (proc.returncode, proc.stdout or "")


def run_inactive_graph_check(root: pathlib.Path) -> list[str]:
    text = read_text(root / "Cargo.lock")
    if text is None:
        return ["inactive-graph check cannot run: missing Cargo.lock"]
    if lockfile_has_inactive(text):
        # Observed behavior (cargo 1.94.1): an inactive
        # optional package present in Cargo.lock but absent from the active
        # all-features/all-targets graph exits 0 with "warning: nothing to
        # print." and no "crypto-bigint v0.5.5" line. A truly absent spec
        # exits 101 with "did not match any packages". A non-zero exit here
        # therefore indicates tool/lock inconsistency, not clean absence, and
        # fails closed to force investigation rather than silently passing.
        result = run_cargo_tree(root, ("-i", INACTIVE_PACKAGE_SPEC))
        if isinstance(result, str):
            return [result]
        returncode, output = result
        if INACTIVE_PACKAGE_VERSION in output:
            return [
                "inactive-graph check FAILED: %s appears in the active "
                "all-features/all-targets graph; remove the audit exception"
                % INACTIVE_PACKAGE_VERSION
            ]
        if returncode != 0:
            return [
                "inactive-graph check FAILED: cargo tree exited %d:\n%s"
                % (returncode, output.strip())
            ]
        return []
    result = run_cargo_tree(root, ("--prefix", "none"))
    if isinstance(result, str):
        return [result]
    returncode, output = result
    if returncode != 0:
        return [
            "positive active-graph check FAILED: cargo tree exited %d:\n%s"
            % (returncode, output.strip())
        ]
    active_versions: list[str] = []
    malformed: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped.startswith("crypto-bigint"):
            continue
        match = ACTIVE_VERSION_RE.match(stripped)
        if match is None:
            malformed.append(stripped)
            continue
        active_versions.append(match.group(1))
    if malformed:
        return [
            "positive active-graph check FAILED: malformed active crypto-bigint "
            "line(s): %s" % "; ".join(malformed)
        ]
    unpatched = sorted(
        {
            version
            for version in active_versions
            if (parse_dotted_version(version) or ()) < PATCHED_MINIMUM
        }
    )
    if unpatched:
        return [
            "positive active-graph check FAILED: active crypto-bigint below the "
            "patched >=0.7.6 line: %s" % ", ".join("v%s" % v for v in unpatched)
        ]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline E-02/E-07 toolchain and advisory guard.")
    parser.add_argument(
        "--require-inactive",
        action="store_true",
        help="also run the cargo-tree active/inactive graph checks",
    )
    parser.add_argument(
        "--root",
        default=str(default_root()),
        help="repository root to check (default: parent of support/)",
    )
    args = parser.parse_args(argv)
    root = pathlib.Path(args.root)
    errors = run_static_checks(root)
    if args.require_inactive:
        errors.extend(run_inactive_graph_check(root))
    if errors:
        print("dependency policy check FAILED:", file=sys.stderr)
        for error in errors:
            print("  - %s" % error, file=sys.stderr)
        return 1
    lock_text = read_text(root / "Cargo.lock")
    if lock_text is not None and not lockfile_has_inactive(lock_text):
        print(
            "dependency policy check passed "
            "(crypto-bigint 0.5.5 is absent from Cargo.lock; advisory entry "
            "cleared and the cargo audit exception is absent from CI)"
        )
        return 0
    suffix = " (including inactive-graph check)" if args.require_inactive else ""
    print("dependency policy check passed%s" % suffix)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
