#!/usr/bin/env python3
"""Fail if a workflow uses a mutable external action reference."""

from __future__ import annotations

import pathlib
import re
import sys


USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
IMMUTABLE_SHA = re.compile(r"[0-9a-f]{40}\Z")


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
    forbidden = (
        "secrets.",
        "TESTNET_RELEASE_SIGNING_KEY",
        "ASTATINE_RELEASE_SIGNING_KEY",
        "contents: write",
        "gh release create",
    )
    for token in forbidden:
        if token in contents:
            raise AssertionError(f"{workflow}: workflow must not contain privileged release authority: {token}")


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
        "run: gh release create v0.1.0-testnet.13",
    ):
        try:
            validate_signing_isolation(privileged, pathlib.Path("synthetic-workflow.yml"))
        except AssertionError:
            continue
        raise AssertionError(f"workflow isolation fixture unexpectedly accepted: {privileged}")


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
