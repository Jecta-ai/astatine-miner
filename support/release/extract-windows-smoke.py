#!/usr/bin/env python3
"""Extract the exact Windows archive validation script from release.yml.

Single source of truth is the inline ``Extract Windows archive to sandbox``
``run: |`` block in ``.github/workflows/release.yml`` (the release job has no
checkout, so the block itself is the trusted acceptance path). Pre-tag CI on
a native Windows runner extracts this block verbatim and executes it against
realistic deterministic synthetic ZIPs, so the release acceptance code and
the tested code are byte-identical -- no duplicated PowerShell copy can drift.

Stdlib-only, offline, no execution. Fails closed when the step or block
markers are missing or ambiguous.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

STEP_MARKER = "Extract Windows archive to sandbox"


def extract_run_block(workflow_text: str) -> str:
    lines = workflow_text.splitlines()
    step_idx: int | None = None
    for i, line in enumerate(lines):
        if STEP_MARKER in line and re.match(r"^\s*-\s*name\s*:", line):
            step_idx = i
            break
    if step_idx is None:
        raise ValueError("windows extract step not found")
    # Exactly one such step must exist.
    for j in range(step_idx + 1, len(lines)):
        if STEP_MARKER in lines[j] and re.match(r"^\s*-\s*name\s*:", lines[j]):
            raise ValueError("multiple windows extract steps found")
    run_idx: int | None = None
    run_indent: int | None = None
    for i in range(step_idx, len(lines)):
        m = re.match(r"^(\s*)run\s*:\s*\|\s*$", lines[i])
        if m:
            run_idx = i
            run_indent = len(m.group(1))
            break
        # Stop at the next step: a new `- name:` at step indent means the
        # extract step has no run block (fail closed).
        if i > step_idx and re.match(r"^\s*-\s*name\s*:", lines[i]):
            break
    if run_idx is None or run_indent is None:
        raise ValueError("windows extract run block not found")
    prefix = run_indent + 2
    collected: list[str] = []
    for k in range(run_idx + 1, len(lines)):
        raw = lines[k]
        if not raw.strip():
            collected.append("")
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent <= run_indent:
            break
        if len(raw) < prefix:
            raise ValueError(f"run block line under-indented: {raw!r}")
        collected.append(raw[prefix:])
    # Strip trailing blank lines but require non-empty code.
    while collected and not collected[-1].strip():
        collected.pop()
    if not any(line.strip() for line in collected):
        raise ValueError("extracted run block is empty")
    return "\n".join(collected) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract exact Windows smoke validation script from release.yml")
    parser.add_argument("--workflow", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        text = args.workflow.read_text(encoding="utf-8")
    except OSError as error:
        print(f"cannot read workflow: {error}", file=sys.stderr)
        return 1
    try:
        block = extract_run_block(text)
    except ValueError as error:
        print(f"extraction failed: {error}", file=sys.stderr)
        return 1
    try:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive write: never overwrite an existing extracted script silently.
        if args.out.exists():
            print(f"refusing to overwrite existing output: {args.out}", file=sys.stderr)
            return 1
        args.out.write_text(block, encoding="utf-8")
    except OSError as error:
        print(f"cannot write output: {error}", file=sys.stderr)
        return 1
    print(f"extracted {len(block.splitlines())} lines to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
