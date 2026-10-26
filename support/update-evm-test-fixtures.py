#!/usr/bin/env python3
"""Refresh test-only creation bytecode from a pinned local astatineEVM Forge build."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


CONTRACTS = {
    "AstatineMiner": "AstatineMiner.sol/AstatineMiner.json",
    "MockAST": "MockAST.sol/MockAST.json",
}
SOURCE_COMMIT = "eb9ea498ed4da10536cd6b4d5d8b55cf38e8aa30"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evm_root", type=Path, help="path to the built astatineEVM/evm checkout")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "tests" / "fixtures",
    )
    args = parser.parse_args()

    source_commit = subprocess.check_output(
        ["git", "-C", str(args.evm_root), "rev-parse", "HEAD"], text=True
    ).strip()
    if source_commit != SOURCE_COMMIT:
        raise SystemExit(
            f"expected astatineEVM commit {SOURCE_COMMIT}, found {source_commit}"
        )

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    for contract, artifact_path in CONTRACTS.items():
        artifact = json.loads((args.evm_root / "out" / artifact_path).read_text())
        bytecode = artifact["bytecode"]["object"]
        if not isinstance(bytecode, str) or not bytecode or bytecode.startswith("__"):
            raise SystemExit(f"{contract} artifact does not contain linked creation bytecode")
        fixture = {
            "source_commit": source_commit,
            "contract": contract,
            "bytecode": {"object": bytecode},
        }
        (output / f"{contract}.json").write_text(
            json.dumps(fixture, indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
