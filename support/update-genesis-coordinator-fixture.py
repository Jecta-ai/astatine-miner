#!/usr/bin/env python3
"""Refresh the test-only Coordinator creation bytecode fixture from its pinned source."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


SOURCE_COMMIT = "54588aa7b020cd7e49fa2275a560cde8138dd707"
ARTIFACT_RELATIVE_PATH = Path("out/AstatineGenesisCoordinator.sol/AstatineGenesisCoordinator.json")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("coordinator_root", type=Path, help="pinned astatine-coordinator checkout")
    parser.add_argument(
        "--artifact",
        type=Path,
        help="compiled Forge artifact (defaults to coordinator_root/out/...)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "tests"
        / "fixtures"
        / "AstatineGenesisCoordinator.json",
    )
    args = parser.parse_args()

    source_commit = subprocess.check_output(
        ["git", "-C", str(args.coordinator_root), "rev-parse", "HEAD"], text=True
    ).strip()
    if source_commit != SOURCE_COMMIT:
        raise SystemExit(
            f"expected Coordinator source commit {SOURCE_COMMIT}, found {source_commit}"
        )

    artifact_path = args.artifact or (args.coordinator_root / ARTIFACT_RELATIVE_PATH)
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    bytecode = artifact.get("bytecode", {}).get("object")
    if not isinstance(bytecode, str) or not bytecode.startswith("0x") or len(bytecode) <= 2:
        raise SystemExit("Coordinator artifact has no complete creation bytecode")
    if "__" in bytecode:
        raise SystemExit("Coordinator creation bytecode contains unresolved library links")

    fixture = {
        "source_commit": source_commit,
        "contract": "AstatineGenesisCoordinator",
        "compiler": {
            "version": "0.8.28",
            "evm_version": "shanghai",
            "optimizer": True,
            "optimizer_runs": 200,
            "bytecode_hash": "none",
        },
        "bytecode": {"object": bytecode},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
